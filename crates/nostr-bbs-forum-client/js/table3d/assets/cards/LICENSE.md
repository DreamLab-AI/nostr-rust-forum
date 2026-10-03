# Court figures: provenance and licence

The twelve court cards (J, Q, K of each suit) are **Dmitry Fomin's
_English pattern playing cards deck_**, from Wikimedia Commons,
dedicated to the public domain under **CC0 1.0**
(https://creativecommons.org/publicdomain/zero/1.0/). No attribution is
required; it is given here because it is deserved.

- Category: https://commons.wikimedia.org/wiki/Category:SVG_English_pattern_playing_cards
- Author: https://commons.wikimedia.org/wiki/User:Dmitry_Fomin
- Fetched 2026-10-03 through the Commons API; each SVG's SHA-1 matched the
  one Commons publishes for it.

## How these files were made

Each SVG was rasterised with ImageMagick and quantised to a 24-colour PNG:

```
magick -density 192 -background white "English pattern <rank> of <suit>.svg" \
       -resize 480x720 -shave 6x6 -colors 24 -define png:compression-level=9 \
       -strip PNG8:<rank>-<suit>.png
```

`-shave` removes the card's own outline (the 3D card has its own edge). The
flat colours of the English pattern survive 24-colour quantisation without
visible loss, at about a fifth of the size of the source SVG. The corner
indices are painted over in the browser with the table's own typeface
(`card-faces.js`, `FOMIN_INDEX`), so the four-colour deck reaches the
courts' indices too; the art itself is unmodified.

| File | Source SVG (SHA-1, as published by Commons) | PNG SHA-256 |
|---|---|---|
| `jack-clubs.png` | `English pattern jack of clubs.svg` (`128300e71730a491215145c9ebc0b0493e775a42`) | `400e7cefa7d4d9b7dd7cbd7d800333dbf83c9e61feacc05c06671ae1cfe7ac36` |
| `jack-diamonds.png` | `English pattern jack of diamonds.svg` (`3c3863caf9740be3b3e922dffd9cdf1ae2fde0b3`) | `42a2f40dea427c69efbcedb7eea14590d657a03978233b4f27f43b4cacaf4826` |
| `jack-hearts.png` | `English pattern jack of hearts.svg` (`922d2a9e56aea084c72d0009b48839533c129d37`) | `9a093c1993ac927e10077874160a2fdfd96c1ea6fa02d55fc609a4d757e4623a` |
| `jack-spades.png` | `English pattern jack of spades.svg` (`38650cf0b1b814ef57f64c90de64b78375c77490`) | `cf278f167e4482b8561adc037592dab628f334493cb2e5e208c8bcdb218074ae` |
| `queen-clubs.png` | `English pattern queen of clubs.svg` (`1557f58ced0d1276aa3527913bce1e41e7d3b377`) | `52e51ab9b3a154caaab21160e155a899e2f755dba54b0811bc33d2f3128f225b` |
| `queen-diamonds.png` | `English pattern queen of diamonds.svg` (`837c80a400421add43ed7152235be65224b3a49d`) | `7e936c53796f6567a5981b7a38bc50e86f4241772367f05931469695810e8dd9` |
| `queen-hearts.png` | `English pattern queen of hearts.svg` (`14a295b2888296db7066c85e06304f05e156ed5c`) | `a4a26dedfca809cb12049106c39f29087c42715683f7e71f32130e868124395f` |
| `queen-spades.png` | `English pattern queen of spades.svg` (`43c2f5a8c2a99e4badd65e0b3680a3662d568bd1`) | `e9e34bea7a1c8b3782261068017ada674074c9b24ae8c29c6b0199f016526371` |
| `king-clubs.png` | `English pattern king of clubs.svg` (`c31c3bcbb46382c80754201bc75029f3397d10f5`) | `2cea7ec27d219a9707b82696def9b02a6ba7b225d19d6d890ae8ebb35075d62c` |
| `king-diamonds.png` | `English pattern king of diamonds.svg` (`742ec97e535381a34710865eb19bcd84732cb9b2`) | `b19e6c415ac8c5dfe9f4ea19599eb373622939ee74e81d7ad8a19dc632273e23` |
| `king-hearts.png` | `English pattern king of hearts.svg` (`7d0ff92fc97dd050952a084772d6a3e29b9fb667`) | `20a7fb25da89e5d12f9ef8ec0b89ee11290a7de793e1c457e6a9c5fd76c3cf47` |
| `king-spades.png` | `English pattern king of spades.svg` (`a3ac0a3635c88f8d9c5b3a62116164a479599fdd`) | `2d8f548f1e07e25e8387ff3ee9a6a09b9f83e8eded67e772fd7b5728a90447c9` |
