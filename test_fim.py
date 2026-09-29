import os
import tempfile

from fim import compare, snapshot


def test_detects_every_change_type():
    with tempfile.TemporaryDirectory() as d:
        for name, text in (("a.txt", "one"), ("b.txt", "two"), ("c.txt", "three")):
            with open(os.path.join(d, name), "w") as f:
                f.write(text)
        before = snapshot(d)
        with open(os.path.join(d, "a.txt"), "w") as f:
            f.write("tampered")
        os.remove(os.path.join(d, "b.txt"))
        os.chmod(os.path.join(d, "c.txt"), 0o777)
        with open(os.path.join(d, "new.txt"), "w") as f:
            f.write("x")
        kinds = {(k, p) for k, p, _ in compare(before, snapshot(d))}
        assert kinds == {("MODIFIED", "a.txt"), ("DELETED", "b.txt"), ("PERMISSIONS", "c.txt"), ("ADDED", "new.txt")}


def test_no_false_positives():
    with tempfile.TemporaryDirectory() as d:
        with open(os.path.join(d, "a.txt"), "w") as f:
            f.write("same")
        assert compare(snapshot(d), snapshot(d)) == []


if __name__ == "__main__":
    test_detects_every_change_type(); test_no_false_positives()
    print("all tests passed")
