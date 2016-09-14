lint:
	pyflakes $$(find -name '*.py') $$(grep '^#!.*python' $$(bzr ls -Vkfile) -l)
check:
	python3 -m unittest rscalib.tests
.PHONY: lint check
