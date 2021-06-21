extern crate clap;
extern crate crossbeam;
#[macro_use]
extern crate lazy_static;

use clap::{App, Arg};
use indicatif::ProgressBar;
use std::cmp::Ordering;
use std::collections::{HashMap, HashSet};
use std::fs::File;
use std::io::{self, BufRead};
use std::iter::FromIterator;
use std::str;
use std::sync::Arc;
use std::thread;

mod cleartexts;
mod matcher;
mod rules;

lazy_static! {
    static ref CONVS: rules::Converts = rules::make_converts();
}

fn worker_thread(
    r: crossbeam::channel::Receiver<Vec<rules::Rule>>,
    s: crossbeam::channel::Sender<HashMap<Vec<rules::Rule>, Vec<u64>>>,
    alines: Arc<Vec<Vec<u8>>>,
    aclear: Arc<HashMap<Vec<u8>, Vec<(Vec<u8>, Vec<u8>, u64)>>>,
    cutoff: usize,
) {
    while let Ok(rules) = r.recv() {
        let hits = matcher::worker_logic(rules, &alines, &aclear, cutoff);
        s.send(hits).unwrap();
    }
}

fn read_wordlist(wordlist: &str) -> Vec<Vec<u8>> {
    let file = File::open(wordlist).unwrap();
    let rdr = io::BufReader::new(file);
    // collect all lines into a shared arc, removing those that are already known
    let mut all_lines = Vec::new();
    for rawline in rdr.split(b'\n') {
        let line = rawline.unwrap();
        all_lines.push(line);
    }
    all_lines
}

fn shorter_rules(a: &[rules::Rule], b: &[rules::Rule]) -> bool {
    let la = rules::show_rules(a, false).len();
    let lb = rules::show_rules(b, false).len();
    la < lb || (la == lb && a < b)
}

fn sub_set(a: &[u64], b: &[u64]) -> Vec<u64> {
    let mut o = Vec::new();
    let mut ai = a.iter();
    let mut bi = b.iter();
    let mut ma = ai.next();
    let mut mb = bi.next();
    loop {
        match (ma, mb) {
            (Some(cura), Some(curb)) => match cura.cmp(curb) {
                Ordering::Equal => {
                    ma = ai.next();
                    mb = bi.next();
                }
                Ordering::Greater => {
                    mb = bi.next();
                }
                Ordering::Less => {
                    o.push(*cura);
                    ma = ai.next();
                }
            },
            (None, _) => break,
            (Some(cura), None) => {
                o.push(*cura);
                ma = ai.next();
            }
        }
    }
    o
}

fn main() {
    let matches = App::new("rulesfinder")
        .version("0.1")
        .about("Finds optimal password mangling rules.")
        .author("Synacktiv")
        .arg(Arg::with_name("wordlist")
            .long("wordlist")
            .short("w")
            .value_name("FILE")
            .help("Training wordlist")
            .required(true)
            .takes_value(true))
        .arg(Arg::with_name("cleartexts")
            .long("cleartexts")
            .short("p")
            .value_name("FILE")
            .help("Training clear text passwords")
            .required(true)
            .takes_value(true))
        .arg(Arg::with_name("cutoff")
            .long("cutoff")
            .short("n")
            .value_name("N")
            .help("Minimum amount of passwords cracked for a rule to be kept")
            .required(true)
            .takes_value(true))
        .arg(Arg::with_name("combinations")
            .long("combos")
            .short("c")
            .value_name("N")
            .help("Maximum number of rules comboed (warning, this number results in exponential increase in compexity)")
            .required(false)
            .takes_value(true))
        .arg(Arg::with_name("threads")
            .long("threads")
            .short("t")
            .value_name("N")
            .help("Amount of threads")
            .takes_value(true))
        .arg(Arg::with_name("minsize")
            .long("minsize")
            .value_name("N")
            .help("Minimum size of wordlists fragments (default 4)")
            .takes_value(true))
        .arg(Arg::with_name("hashcat")
            .long("hashcat")
            .help("Only use rules that work in Hashcat")
            .takes_value(false))
        .arg(Arg::with_name("details")
            .long("details")
            .help("Print statistics in the rule output")
            .takes_value(false))
        .get_matches();

    let hashcat_mode = matches.is_present("hashcat");
    let details_mode = matches.is_present("details");
    let allrules = rules::genmutate()
        .into_iter()
        .filter(|rs| {
            if hashcat_mode {
                rs.iter().all(rules::hashcat_rule)
            } else {
                rs.iter().all(rules::john_rule)
            }
        })
        .collect::<Vec<_>>();
    let minsize = match matches.value_of("minsize") {
        Some(ms) => ms.parse::<usize>().unwrap(),
        None => 4,
    };

    let wordlist = matches.value_of("wordlist").unwrap();
    let cleartexts = matches.value_of("cleartexts").unwrap();
    let scombos = matches.value_of("combos").unwrap_or("1");
    let combos = scombos.parse::<u64>().unwrap();
    let cutoff = matches
        .value_of("cutoff")
        .unwrap()
        .parse::<usize>()
        .unwrap();
    let nthreads = matches
        .value_of("threads")
        .unwrap_or("4")
        .parse::<usize>()
        .unwrap();

    if combos != 1 {
        panic!("combos must be 1 for now");
    }

    let vwordlist = read_wordlist(wordlist);
    let swordlist = HashSet::from_iter(&vwordlist);
    let (clearmap, _) = cleartexts::process(cleartexts, minsize, &swordlist).unwrap();

    let arc_lines = Arc::new(vwordlist);
    let arc_clear = Arc::new(clearmap);

    // create channels for each threads
    let (send_rule, recv_rule) = crossbeam::channel::bounded(128);
    let (send_hits, recv_hits) = crossbeam::channel::bounded(128);

    for _ in 0..nthreads {
        let rcv = recv_rule.clone();
        let snd = send_hits.clone();
        let c_lines = arc_lines.clone();
        let c_clear = arc_clear.clone();
        thread::spawn(move || worker_thread(rcv, snd, c_lines, c_clear, cutoff));
    }

    let rules_count = allrules.len();

    // send all rules in the queue
    thread::spawn(move || {
        for rule in allrules.iter() {
            send_rule.send(rule.clone()).unwrap();
        }
    });

    // receive all results
    let mut hits: HashMap<Vec<rules::Rule>, Vec<u64>> = HashMap::new();

    let progress = ProgressBar::new(rules_count as u64);
    progress
        .set_style(indicatif::ProgressStyle::default_bar().template(
            "[ETA: {eta_precise}] {bar:60.cyan/blue} {pos}/{len} - {msg} rules retained",
        ));
    let mut retained = 0;
    for _ in 0..rules_count {
        let cur_hits = recv_hits.recv().unwrap();
        progress.set_message(retained.to_string().as_str());
        progress.inc(1);
        retained += cur_hits.len();
        hits.extend(cur_hits);
    }
    progress.finish();

    if !hashcat_mode {
        println!("!! hashcat logic ON");
    }

    // greedy coverage
    let mut last_set: Vec<u64> = Vec::new();
    let mut total_cracked = 0;
    while !hits.is_empty() {
        let mut best_rules: Vec<rules::Rule> = vec![];
        let mut best_count: usize = 0;
        let mut best_set: Vec<u64> = Vec::new();
        let mut to_remove: Vec<Vec<rules::Rule>> = Vec::new();
        for im in hits.iter_mut() {
            // early cutoff
            if im.1.len() < cutoff {
                to_remove.push(im.0.clone());
                continue;
            }
            *im.1 = sub_set(im.1, &last_set);
            // deferred cutoff
            if im.1.len() < cutoff {
                to_remove.push(im.0.clone());
                continue;
            }
            let curlen = im.1.len();
            if curlen > best_count || (curlen == best_count && shorter_rules(im.0, &best_rules)) {
                best_count = curlen;
                best_rules = im.0.clone();
                best_set = im.1.clone();
            }
        }
        for rm in to_remove {
            hits.remove(&rm);
        }
        hits.remove(&best_rules);
        last_set = best_set;
        if best_count > 0 {
            total_cracked += best_count;
            // do not print the final loop, where 'hits' is empty and nothing was found!
            if details_mode {
                println!(
                    "{} // [{} - {}]",
                    rules::show_rules(&best_rules, hashcat_mode),
                    best_count,
                    total_cracked
                );
            } else {
                println!("{}", rules::show_rules(&best_rules, hashcat_mode));
            }
        }
    }

    if !hashcat_mode {
        println!("!! hashcat logic OFF");
    }

    // without this, it takes a long time to free the large "hits" hashmap
    std::process::exit(0);
}
