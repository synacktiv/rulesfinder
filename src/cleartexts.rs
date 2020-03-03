
use std::fs::File;
use std::io::{self, BufRead};
use std::collections::{HashSet, HashMap};
use indicatif::{ProgressBar};

pub fn process_line(
    out : &mut HashMap<Vec<u8>, Vec<(Vec<u8>, Vec<u8>, u64)>>,
    nth: u64,
    line: &Vec<u8>,
    minsize: usize
    ) -> usize {
    let ln = line.len();
    let mut inserted = 0;
    for start in 0 .. 1 + ln - minsize {
        let maxwidth = 1 + ln - start;
        for sz in minsize .. maxwidth {
            let middle = line[start .. start+sz].to_vec();
            inserted += 1;
            out.entry(middle)
                .and_modify(|x : &mut Vec<(Vec<u8>, Vec<u8>, u64)>| {
                    let lstart = line[0 .. start].to_vec();
                    let ending = line[start+sz ..].to_vec();
                    x.push( (lstart, ending, nth) );
                })
                .or_insert({
                    let lstart = line[0 .. start].to_vec();
                    let ending = line[start+sz ..].to_vec();
                    vec![(lstart, ending, nth)]
                });
            }
    }
    return inserted;
}

// returns a map with all the fragments, and a hashset with all the lines
pub fn process(path: &str, minsize: usize, known: &HashSet<&Vec<u8>>) ->
    io::Result<(
        HashMap<Vec<u8>, Vec<(Vec<u8>, Vec<u8>, u64)>>,
        HashMap<u64, Vec<u8>>
        ) > {
    let mut idx = HashMap::new();

    let file = File::open(path)?;
    let rdr = io::BufReader::new(file);
    let mut i = 0;
    let mut inserted = 0;
    let mut expected_size = 0;

    for rline in rdr.split('\n' as u8) {
        let line = rline?;
        let llen = line.len();
        if llen < minsize || known.contains(&line) {
            continue;
        }
        idx.insert(i, line);
        i += 1;
        for l in minsize..llen+1 {
            expected_size += llen + 1 - l;
        }
    }

    // TODO : there is a saturation of low length hashes that can be computed statistically
    // this will reserve way too much space here, but it is not too bad, as this is nothing
    // compared to what's inside the map ...
    let mut out = HashMap::with_capacity(expected_size * 7 / 10);
    let bar = ProgressBar::new(i);
    bar.set_style(indicatif::ProgressStyle::default_bar()
        .template("[ETA: {eta_precise}] {bar:60.cyan/blue} {pos}/{len} - {msg} fragments inserted"));
    i = 0;
    for (k, line) in &idx {
        inserted += process_line(&mut out, *k, &line, minsize);
        i += 1;
        if i % 2000 == 0 {
            bar.set_message(inserted.to_string().as_str());
            bar.set_position(i);
        }
    }
    bar.finish();

    return Ok((out, idx));
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test1() {
        let mut out = HashMap::new();
        let inserted = process_line(&mut out, 0, &"ABCDEF".as_bytes().to_vec(), 3);
        let expected : &[(&str, (&str, &str))] = &[
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
        for (k, tpl) in expected {
            let kv : Vec<u8> = k.as_bytes().to_vec();
            match out.get(&kv) {
                None => panic!("Could not find match {}", k),
                Some(_) => {}
            }
        }
        assert_eq!(expected.len(), out.len());
    }
}
