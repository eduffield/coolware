Here is some quick directions on where some things are for grading.

Our code is in the /src/ directory. /src/final/ is the final version
of the program, the other directories are developmental branches.
Since you dont want to setup any cloud environments, just run main.py with
'viewreport' as an argument to see examples of the reports we generated.

Our documentation, written by Bennett, is in the /docs/ directory.
Also included in /docs/presentation is the pdf of the presentation.

To run the program, have python installed and follow the directions in the
README.md

Testing was done in several ways by Evan. He carried out user-acceptance Testing
on the UI to find bugs, and the Report.py file has its main function generate a
larger than normal report to test the ui. Integration testing was done with the modules
during our second prototype that would allow us to eventually pass one Report object through
multiple vendors in one run. Finally, in the /terraform/ directory, are some examples of the test
environments we deployed with the vendors to test if our script works. pytest.py was used to compare
the expected number of issues generated in a report compared to what actually was returned.