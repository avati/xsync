Summary: xtime based remote synchronization for glusterfs
Name: xsync
Version: 0.0.1
Release: 1%{?dist}
License: LGPLv3
Group: System Environment/Base
URL: http://github.com/avati/xsync/downloads/%{name}-%{version}.tar.gz
Source0: %{name}-%{version}.tar.gz
BuildArch: noarch
BuildRoot: %{_tmppath}/%{name}-%{version}-%{release}-root-%(%{__id_u} -n)

%description
xtime based remote synchronization for glusterfs (crawling from the backend)

%prep
%setup -q -n %{name}-%{version}

%install
rm -rf $RPM_BUILD_ROOT
mkdir -p $RPM_BUILD_ROOT/usr/bin

install -m755 gsyncd $RPM_BUILD_ROOT/usr/bin/gsyncd
install -m755 xsync $RPM_BUILD_ROOT/usr/bin/xsync

%clean
rm -rf $RPM_BUILD_ROOT

%files
%defattr(-,root,root)
%doc README.md
%{_bindir}/gsyncd
%{_bindir}/xsync

%changelog
* Wed Nov 7 2012 Harshavardhana <fharshav@redhat.com> - 0.0.1-1
- First import - build 
