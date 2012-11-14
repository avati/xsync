Summary: xtime based remote synchronization for glusterfs
Name: glusterfs-xsync
Version: 0.3
Release: 1%{?dist}
License: LGPLv3
Group: System Environment/Base
URL: https://github.com/avati/xsync
Source0: %{name}-%{version}.tar.gz
BuildRoot: %{_tmppath}/%{name}-%{version}-%{release}-root-%(%{__id_u} -n)

%description
xtime based remote synchronization for glusterfs (crawling from the backend)

%prep
%setup -q -n %{name}-%{version}

%build
make all

%install
rm -rf $RPM_BUILD_ROOT
mkdir -p $RPM_BUILD_ROOT/usr/libexec/glusterfs

install -m755 gsyncd $RPM_BUILD_ROOT/usr/libexec/glusterfs/gsyncd
install -m755 xsync.sh $RPM_BUILD_ROOT/usr/libexec/glusterfs/xsync
install -m755 xfind $RPM_BUILD_ROOT/usr/libexec/glusterfs/xfind

%clean
rm -rf $RPM_BUILD_ROOT

%files
%defattr(-,root,root)
%doc README.md
/usr/libexec/glusterfs/gsyncd
/usr/libexec/glusterfs/xsync
/usr/libexec/glusterfs/xfind

%changelog
* Wed Nov 7 2012 Harshavardhana <fharshav@redhat.com> - 0.0.1-1
- First import - build 
