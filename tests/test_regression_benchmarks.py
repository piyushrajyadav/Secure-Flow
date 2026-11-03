"""Guards against detection regressions on the shipped datasets."""
from experiments.evaluate import run


def test_known_datasets_do_not_regress():
    res = run(threshold=60)
    v1 = res["v1 dataset (tuned-on)"]["current"]
    v2 = res["v2 dataset (used in tuning)"]["current"]
    v3 = res["v3 dataset (blind)"]["current"]
    assert v1["asr"] <= 5 and v1["fpr"] == 0
    assert v2["asr"] <= 5 and v2["fpr"] <= 3
    # Blind set: honest numbers. Fail only if it gets WORSE than what was measured at release.
    assert v3["asr"] <= 75 and v3["fpr"] <= 15
