PYTHON=`which python`
PYTHON2=`which python2`
PYTHON3=`which python3`
PY2DSC=`which py2dsc`

topdir := $(realpath $(dir $(lastword $(MAKEFILE_LIST))))
topbuilddir := $(realpath .)

DESTDIR=/
PROJECT=$(shell python $(topdir)/setup.py --name)
VERSION=$(shell python $(topdir)/setup.py --version)
MODNAME=$(PROJECT)

# The rules for names and versions in python, rpm, and deb are different
# and not entirely compatible. As such py2dsc will automatically convert
# your package name into a suitable deb name and version number, and this
# code replicates that.
DEBNAME=$(shell echo $(MODNAME) | tr '[:upper:]_' '[:lower:]-')
DEBVERSION=$(shell echo $(VERSION) | sed 's/\.dev/~dev/')

DEBIANDIR=$(topbuilddir)/deb_dist/$(DEBNAME)-$(DEBVERSION)/debian
DEBIANOVERRIDES=$(patsubst $(topdir)/debian/%,$(DEBIANDIR)/%,$(wildcard $(topdir)/debian/*))

RPM_PARAMS?=
RPM_PREFIX?=$(topdir)/build/rpm

RPMDIRS=BUILD BUILDROOT RPMS SOURCES SPECS SRPMS
RPMBUILDDIRS=$(patsubst %, $(RPM_PREFIX)/%, $(RPMDIRS))

all:
	@echo "$(PROJECT)-$(VERSION)"
	@echo "make source  - Create source package"
	@echo "make install - Install on local system (only during development)"
	@echo "make clean   - Get rid of scratch and byte files"
	@echo "make test    - Test using tox and nose2"
	@echo "make deb     - Create deb package"
	@echo "make dsc     - Create debian source package"
	@echo "make rpm     - Create rpm package"
	@echo "make wheel   - Create whl package"
	@echo "make egg     - Create egg package"
	@echo "make rpm_dirs - Create directories for rpm building"

$(topbuilddir)/dist:
	mkdir -p $@

source: $(topbuilddir)/dist
	$(PYTHON) $(topdir)/setup.py sdist $(COMPILE) --dist-dir=$(topbuilddir)/dist

$(topbuilddir)/dist/$(MODNAME)-$(VERSION).tar.gz: source

install:
	$(PYTHON) $(topdir)/setup.py install --root $(DESTDIR) $(COMPILE)

clean:
	$(PYTHON) $(topdir)/setup.py clean || true
	rm -rf $(topbuilddir)/.tox
	rm -rf $(topbuilddir)/build/ MANIFEST
	rm -rf $(topbuilddir)/dist
	rm -rf $(topbuilddir)/deb_dist
	rm -rf $(topbuilddir)/*.egg-info
	find $(topdir) -name '*.pyc' -delete
	find $(topdir) -name '*.py,cover' -delete

test:
	tox

deb_dist: $(topbuilddir)/dist/$(MODNAME)-$(VERSION).tar.gz
	$(PY2DSC) --with-python2=true --with-python3=false $(topbuilddir)/dist/$(MODNAME)-$(VERSION).tar.gz

$(DEBIANDIR)/%: $(topdir)/debian/% deb_dist
	cp -r $< $@

dsc: deb_dist $(DEBIANOVERRIDES)
	cp $(topbuilddir)/deb_dist/$(DEBNAME)_$(DEBVERSION)-1.dsc $(topbuilddir)/dist

deb: source deb_dist $(DEBIANOVERRIDES)
	cd $(DEBIANDIR)/..;debuild -uc -us
	cp $(topbuilddir)/deb_dist/python*$(DEBNAME)_$(DEBVERSION)-1*.deb $(topbuilddir)/dist

# START OF RPM SPEC RULES
# If you have your own rpm spec file to use you'll need to disable these rules
$(RPM_PREFIX)/$(MODNAME).spec: rpm_spec

rpm_spec: $(topdir)/setup.py
	$(PYTHON3) $(topdir)/setup.py bdist_rpm $(RPM_PARAMS) --spec-only --dist-dir=$(RPM_PREFIX)
# END OF RPM SPEC RULES

$(RPMBUILDDIRS):
	mkdir -p $@

$(RPM_PREFIX)/SPECS/$(MODNAME).spec: $(RPM_PREFIX)/$(MODNAME).spec $(RPM_PREFIX)/SPECS
	rm -rf $@
	cp -f $< $@

$(RPM_PREFIX)/SOURCES/$(MODNAME)-$(VERSION).tar.gz: $(topbuilddir)/dist/$(MODNAME)-$(VERSION).tar.gz $(RPM_PREFIX)/SOURCES
	rm -rf $@
	cp -f $< $@

rpm_dirs: $(RPMBUILDDIRS) $(RPM_PREFIX)/SPECS/$(MODNAME).spec $(RPM_PREFIX)/SOURCES/$(MODNAME)-$(VERSION).tar.gz

rpm: $(RPM_PREFIX)/SPECS/$(MODNAME).spec $(RPM_PREFIX)/SOURCES/$(MODNAME)-$(VERSION).tar.gz $(RPMBUILDDIRS)
	rpmbuild -ba --define '_topdir $(RPM_PREFIX)' --clean $<
	cp $(RPM_PREFIX)/RPMS/*/*.rpm $(topbuilddir)/dist

wheel:
	$(PYTHON2) $(topdir)/setup.py bdist_wheel
	$(PYTHON3) $(topdir)/setup.py bdist_wheel

egg:
	$(PYTHON2) $(topdir)/setup.py bdist_egg
	$(PYTHON3) $(topdir)/setup.py bdist_egg

.PHONY: test test2 test3 clean install source deb dsc rpm wheel egg all rpm_dirs rpm_spec
