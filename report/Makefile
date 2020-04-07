PREFIX=/usr/local/teTeX/bin/

LATEX=latex
BIBTEX=bibtex
PDFLATEX=pdflatex
DOC=paper
SRC=paper.tex 

all: $(DOC).pdf

$(DOC).dvi: $(DOC).tex $(SRC) Makefile 
	-$(LATEX) $(DOC)
	-$(BIBTEX)  -min-crossrefs=100 $(DOC)
	-$(LATEX) $(DOC)
	-$(LATEX) $(DOC)

$(DOC).pdf: $(DOC).tex $(SRC) Makefile 
	-$(PDFLATEX) $(DOC)
	-$(BIBTEX)  -min-crossrefs=100 $(DOC)
	-$(PDFLATEX) $(DOC)
	-$(PDFLATEX) $(DOC)

clean:
	rm -f *.aux *.dvi *.idx *.ilg *.ind *.log *.toc *.out *.bak *~ \
	$(DOC).bbl $(DOC).blg $(DOC).ps $(DOC).spl $(DOC).pdf

