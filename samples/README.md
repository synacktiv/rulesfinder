# Sample rules

While the focus of this tool is to quickly create engagement-specific wordlists, this
directory contains pre-generated rules that demonstrate how the tool can be used.

## jtrwordlist_yahoo.rules

This file was generated using the following command, where `password.lst` is the wordlist
bundled with John the Ripper, and `2012-07-yahoo` is the 2012 Yahoo leak.

```shell
cargo run --release --  -w ~/tools/JohnTheRipper/run/password.lst \
  --cleartexts /dictionnaries/2012-07-yahoo -n 30 -t 7 --minsize 3 --details
```

## wikipedia2009_yahoo.rules

This one was generated with a huge cracking dictionnary (a Wikipedia dump from
Sébastien Raveau) and the yahoo leak. The rule quality seems pretty bad, as
it starts with:

```
sI1$1
l
T0Az"123"
Rm
T0Az"12"
Rm$1
Rm$9
Rm$3
Rm$2
l$2
Rm$7
sa4se3si1so0ss5sA4sE3sI1sO0sS5A0"12"$6
Rm$8
T0Az"11"
om1Az"234"
O66
Rm$5
Rm$4
Rm$0
```

The `R` rule shifts characters right, by keyboard. As the dictionnary gets larger,
these rules become more common as they generate words that do not have a lot of
overlap with the original dictionnary.

It was generated with the following parameters:

```shell
cargo run --release --  -w ~/tools/JohnTheRipper/run/password.lst \
  --cleartexts /dictionnaries/wikipedia-wordlist-sraveau-20090325.txt \
   -n 50 -t 7 --minsize 3
```

