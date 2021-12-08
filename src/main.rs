use indicatif::ProgressBar;
use std::cmp::Ordering;
use std::collections::{HashMap, HashSet};
use std::fs::File;
use std::io::{self, BufRead};
use std::iter::FromIterator;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::thread;
use structopt::StructOpt;

mod cleartexts;
mod matcher;
mod rules;

lazy_static::lazy_static! {
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

fn read_wordlist(wordlist: &Path) -> Vec<Vec<u8>> {
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

#[derive(Debug, StructOpt)]
#[structopt(name = "rulesfinder", about = "Finds optimal password mangling rules.")]
struct Options {
    /// Training wordlist path
    #[structopt(long = "wordlist", short = "w", parse(from_os_str))]
    wordlist: PathBuf,
    /// Training clear text passwords
    #[structopt(long = "cleartexts", short = "p", parse(from_os_str))]
    cleartexts: PathBuf,
    /// Minimum amount of passwords cracked for a rule to be kept
    #[structopt(long = "cutoff", short = "n", name = "LEN")]
    cutoff: usize,
    /// Maximum number of rules comboed (warning, this number results in exponential increase in complexity)
    #[structopt(long = "combos", short = "c", name = "CB", default_value("1"))]
    combinations: u64,
    /// Amount of threads
    #[structopt(long = "threads", short = "t", name = "THREADS", default_value("4"))]
    threads: u64,
    /// Minimum size of wordlists fragments
    #[structopt(long = "minsize", name = "SIZE", default_value("4"))]
    minsize: usize,
    /// Only use rules taht work in Hashcat
    #[structopt(long = "hashcat")]
    hashcat: bool,
    /// Print statistics in the rule output
    #[structopt(long = "details")]
    details: bool,
}

fn main() {
    let opt = Options::from_args();
    let allrules = rules::genmutate()
        .into_iter()
        .filter(|rs| {
            if opt.hashcat {
                rs.iter().all(rules::hashcat_rule)
            } else {
                rs.iter().all(rules::john_rule)
            }
        })
        .collect::<Vec<_>>();

    if opt.combinations != 1 {
        panic!("combos must be 1 for now");
    }

    let vwordlist = read_wordlist(&opt.wordlist);
    let swordlist = HashSet::from_iter(&vwordlist);
    let (clearmap, _) = cleartexts::process(&opt.cleartexts, opt.minsize, &swordlist).unwrap();

    let arc_lines = Arc::new(vwordlist);
    let arc_clear = Arc::new(clearmap);

    // create channels for each threads
    let (send_rule, recv_rule) = crossbeam::channel::bounded(128);
    let (send_hits, recv_hits) = crossbeam::channel::bounded(128);

    let cutoff = opt.cutoff;
    for _ in 0..opt.threads {
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

    if !opt.hashcat {
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
            if im.1.len() < opt.cutoff {
                to_remove.push(im.0.clone());
                continue;
            }
            *im.1 = sub_set(im.1, &last_set);
            // deferred cutoff
            if im.1.len() < opt.cutoff {
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
            if opt.details {
                println!(
                    "{} // [{} - {}]",
                    rules::show_rules(&best_rules, opt.hashcat),
                    best_count,
                    total_cracked
                );
            } else {
                println!("{}", rules::show_rules(&best_rules, opt.hashcat));
            }
        }
    }

    if !opt.hashcat {
        println!("!! hashcat logic OFF");
    }

    // without this, it takes a long time to free the large "hits" hashmap
    std::process::exit(0);
}
