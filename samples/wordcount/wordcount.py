"""Count words in text read from standard input."""
import sys


def count_words(text):
    counts = {}
    for word in text.split(" "):
        counts[word] = counts.get(word, 0) + 1
    return counts


def main():
    counts = count_words(sys.stdin.read())
    for word, n in sorted(counts.items()):
        print(f"{word} {n}")


if __name__ == "__main__":
    main()
