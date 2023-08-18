use crate::rules::genmutate;
use crate::rules::mutate;
use std::fs::File;
use std::io::prelude::*;
use std::io::BufReader;
use structopt::StructOpt;

mod rules;

lazy_static::lazy_static! {
    static ref CONVS: rules::Converts = rules::make_converts();
}

#[derive(Debug)]
enum Mode {
    DumpRules,
    ApplyRules,
}

impl std::str::FromStr for Mode {
    type Err = &'static str;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "dump" => Ok(Mode::DumpRules),
            "apply" => Ok(Mode::ApplyRules),
            _ => Err("Accepted modes are dump and apply"),
        }
    }
}

#[derive(Debug, StructOpt)]
struct Opts {
    /// Execution mode
    #[structopt(long = "mode", default_value("dump"))]
    mode: Mode,
    /// Only use rules that work in Hashcat
    #[structopt(long = "hashcat")]
    hashcat: bool,
    /// Dictionary to apply rules on
    #[structopt(long = "dict")]
    dict: Option<String>,
}

fn main() {
    let opt = Opts::from_args();
    match opt.mode {
        Mode::DumpRules => {
            if opt.hashcat {
                for r in genmutate()
                    .into_iter()
                    .filter(|rs| rs.iter().all(rules::hashcat_rule))
                {
                    println!(
                        "{}",
                        rules::show_rules(&r, true).expect("invalid rule got printed :(")
                    );
                }
            } else {
                println!("[List.Rules:RulesFinderRaw]");
                for r in genmutate()
                    .into_iter()
                    .filter(|rs| rs.iter().all(rules::hashcat_rule))
                {
                    match rules::show_rules(&r, false) {
                        Some(s) => println!("{}", s),
                        None => {
                            println!("!! hashcat logic ON");
                            println!(
                                "{}",
                                rules::show_rules(&r, true).expect("invalid rule got printed")
                            );
                            println!("!! hashcat logic OFF");
                        }
                    }
                }
            }
        }
        Mode::ApplyRules => {
            let rdict = opt.dict.expect("Missing --dict parameter");
            let file = File::open(rdict).unwrap();
            let reader = BufReader::new(file);
            let rlns: Result<Vec<String>, _> = reader.lines().collect();
            let lns = rlns.unwrap();
            for r in genmutate()
                .into_iter()
                .filter(|rs| rs.iter().all(rules::hashcat_rule))
            {
                // println!("// {:?}", r);
                for l in &lns {
                    if let Some(o) = mutate(l.as_bytes(), &r) {
                        std::io::stdout().write_all(&o).unwrap();
                        std::io::stdout().write_all(b"\n").unwrap();
                    }
                }
            }
        }
    }
}
