all: format

format:
	dart format .

clean:
	git clean -fdx -e .vscode

analyze:
	dart pub global list | grep pana || dart pub global activate pana
	dart pub global run pana --no-warning

publish: format clean
	test -z "$(shell git status --porcelain)"
	dart pub publish -f
	git tag $(shell grep version pubspec.yaml | sed 's/version\s*:\s*/v/g')

.PHONY: format clean publish analyze
