use indicatif::ProgressBar;
use smallvec::SmallVec;
use smallvec::ToSmallVec;
use std::collections::{HashMap, HashSet};
use std::fs::File;
use std::io::{self, BufRead};
use std::path::Path;

pub type CleartextInfo = (SmallVec<[u8; 16]>, SmallVec<[u8; 16]>, u64);

pub type CleartextMap = HashMap<SmallVec<[u8; 16]>, Vec<CleartextInfo>>;

pub fn process_line(out: &mut CleartextMap, nth: u64, line: &[u8], minsize: usize) -> usize {
    let ln = line.len();
    let mut inserted = 0;
    for start in 0..1 + ln - minsize {
        let maxwidth = 1 + ln - start;
        for sz in minsize..maxwidth {
            let middle = line[start..start + sz].to_smallvec();
            inserted += 1;
            out.entry(middle)
                .and_modify(|x: &mut Vec<CleartextInfo>| {
                    let lstart = line[0..start].to_smallvec();
                    let ending = line[start + sz..].to_smallvec();
                    x.push((lstart, ending, nth));
                })
                .or_insert({
                    let lstart = line[0..start].to_smallvec();
                    let ending = line[start + sz..].to_smallvec();
                    vec![(lstart, ending, nth)]
                });
        }
    }
    inserted
}

// returns a map with all the fragments, and a hashset with all the lines
pub fn process(
    preallocate: bool,
    path: &Path,
    minsize: usize,
    known: &HashSet<&Vec<u8>>,
) -> io::Result<(CleartextMap, HashMap<u64, Vec<u8>>)> {
    let mut idx = HashMap::new();

    let file = File::open(path)?;
    let rdr = io::BufReader::new(file);
    let mut i = 0;
    let mut inserted = 0;
    let mut expected_size = 0;

    for rline in rdr.split(b'\n') {
        let line = rline?;
        let llen = line.len();
        if llen < minsize || known.contains(&line) {
            continue;
        }
        idx.insert(i, line);
        i += 1;
        let tta = 1 + llen - minsize;
        expected_size += (tta + 1) * tta / 2;
    }

    // TODO : there is a saturation of low length hashes that can be computed statistically
    // this will reserve way too much space here, but it is not too bad, as this is nothing
    // compared to what's inside the map ...

    let mut out = if preallocate {
        HashMap::with_capacity(expected_size * 7 / 10)
    } else {
        HashMap::new()
    };
    let progress = ProgressBar::new(i);
    progress.set_style(indicatif::ProgressStyle::default_bar().template(
        "[ETA: {eta_precise}] {bar:60.cyan/blue} {pos}/{len} - {msg} fragments inserted",
    ));
    i = 0;
    for (k, line) in &idx {
        inserted += process_line(&mut out, *k, line, minsize);
        i += 1;
        if i % 2000 == 0 {
            progress.set_message(inserted.to_string().as_str());
            progress.set_position(i);
        }
    }
    progress.finish();

    Ok((out, idx))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test1() {
        let mut out = HashMap::new();
        let _inserted = process_line(&mut out, 0, &"ABCDEF".as_bytes().to_vec(), 3);
        let expected: &[(&str, (&str, &str))] = &[
            ("ABCDEF", ("", "")),
            ("ABCDE", ("", "F")),
            ("ABCD", ("", "EF")),
            ("ABC", ("", "DEF")),
            ("BCDEF", ("A", "")),
            ("BCDE", ("A", "F")),
            ("BCD", ("A", "EF")),
            ("CDEF", ("AB", "")),
            ("CDE", ("AB", "F")),
            ("DEF", ("ABC", "")),
        ];
        for (k, _tpl) in expected {
            let kv: SmallVec<[u8; 16]> = k.as_bytes().to_smallvec();
            match out.get(&kv) {
                None => panic!("Could not find match {}", k),
                Some(_) => {}
            }
        }
        assert_eq!(expected.len(), out.len());
    }
}
