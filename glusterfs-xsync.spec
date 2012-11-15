Summary: xtime based remote synchronization for glusterfs
Name: glusterfs-xsync
Version: 0.9
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
install -m755 xsync_files.sh $RPM_BUILD_ROOT/usr/libexec/glusterfs/xsync_files.sh
install -m755 sync_stime.sh $RPM_BUILD_ROOT/usr/libexec/glusterfs/sync_stime.sh
install -m755 xfind $RPM_BUILD_ROOT/usr/libexec/glusterfs/xfind

%clean
rm -rf $RPM_BUILD_ROOT

%files
%defattr(-,root,root)
%doc README.md
/usr/libexec/glusterfs/xsync
/usr/libexec/glusterfs/xsync_files.sh
/usr/libexec/glusterfs/sync_stime.sh
/usr/libexec/glusterfs/xfind

%package gsyncd
Summary: gsyncd replacement for GlusterFS geo replication

%description gsyncd
This package gives a replacement for glusterfs-geo-replication package
and makes glusterfs use xsync based transfer instead

%files gsyncd
%defattr(-,root,root)
/usr/libexec/glusterfs/gsyncd

%changelog
* Wed Nov 7 2012 Harshavardhana <fharshav@redhat.com> - 0.0.1-1
- First import - build
