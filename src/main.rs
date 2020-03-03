extern crate clap;
extern crate crossbeam;

use clap::{App, Arg};
use indicatif::ProgressBar;
use std::collections::BTreeSet;
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

fn worker_thread(
    r: crossbeam::channel::Receiver<Vec<rules::Rule>>,
    s: crossbeam::channel::Sender<HashMap<Vec<rules::Rule>, BTreeSet<u64>>>,
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
        .get_matches();

    let allrules = rules::genmutate();
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
            let vrule = vec![rule.clone()];
            send_rule.send(vrule).unwrap();
        }
    });

    // receive all results
    let mut hits: HashMap<Vec<rules::Rule>, BTreeSet<u64>> = HashMap::new();

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

    // greedy coverage
    let mut last_set: BTreeSet<u64> = BTreeSet::new();
    while !hits.is_empty() {
        let mut best_rules: Vec<rules::Rule> = vec![];
        let mut best_count: usize = 0;
        let mut best_set: BTreeSet<u64> = BTreeSet::new();
        let mut to_remove: Vec<Vec<rules::Rule>> = Vec::new();
        for im in hits.iter_mut() {
            // early cutoff
            if im.1.len() < cutoff {
                to_remove.push(im.0.clone());
                continue;
            }
            *im.1 = &im.1.clone() - &last_set;
            // deferred cutoff
            if im.1.len() < cutoff {
                to_remove.push(im.0.clone());
                continue;
            }
            let curlen = im.1.len();
            if curlen > best_count
                || (curlen == best_count
                    && rules::show_rules(im.0).len() < rules::show_rules(&best_rules).len())
            {
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
            // do not print the final loop, where 'hits' is empty and nothing was found!
            println!("{} // [{}]", rules::show_rules(&best_rules), best_count);
        }
    }
    // without this, it takes a long time to free the large "hits" hashmap
    std::process::exit(0);
}
