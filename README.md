# Qubes R3 Importer

This is a script to import AppVMs directly from a hard drive containing an installation of Qubes OS R3.x to at least Qubes R4-rc1,-rc2.

The preferred way to migrate from Qubes R3 to R4 is still making a full backup (using the Qubes backup system) on the old machine and restore it on the new machine, however that is not always possible due to real-world constraints (no spare disks with sufficient capacity, etc.).
This script lets you migrate VMs directly without making such a backup.

## Usage

```
Usage: import.sh [-y] [-m mapfile] [domain [mount_point]]
  mapfile is a tab-separated list of old and new template names

  To prepare, mount a Qubes R3 disk in "domain" at "mount_point"
  (default domain: sys-usb-trusted, mount_point: /mnt)
  This requires lvm2 to be installed in the target domain.

  Example preparation:
	[user@sys-usb-trusted ~]$ sudo -s
	[root@sys-usb-trusted user]# dnf install lvm2
	[root@sys-usb-trusted user]# lsblk
	[root@sys-usb-trusted user]# cryptsetup luksOpen /dev/sda3 luks
	[root@sys-usb-trusted user]# mount -o ro /dev/qubes_dom0/root /mnt

  The USB VM must be trusted because it will have access to all the
  decrypted VM images of the old machine you are importing from.
  As such, creating a new VM just for this purpose is recommended.
```

## Caveat Emptor

The implementation is awkward and ugly and potentially vulnerable to a malicious USB VM, but you should use a specificly trusted USB VM for this import operation to begin with.
