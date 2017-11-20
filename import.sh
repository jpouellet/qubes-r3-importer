#!/bin/sh

usage() {
	cat <<EOF >&2
Usage: ${0##*/} [-y] [-m mapfile] [domain [mount_point]]
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
EOF
	exit 2
}

while [[ X"$1" = X-* ]]; do
	case "$1" in
	-y)	dash_y=1 ;;
	-m)	tmap=$2; shift; ;;
	*)	usage ;;
	esac
	shift
done

dom=${1:-sys-usb-trusted}
prefix=${2:-/mnt}

: ${vlq:=${prefix}/var/lib/qubes}

# From OpenBSD install.sub
#
# Copyright (c) 1997-2015 Todd Miller, Theo de Raadt, Ken Westerback
# Copyright (c) 2015, Robert Peichaer <rpe@openbsd.org>
#
# All rights reserved.
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions
# are met:
# 1. Redistributions of source code must retain the above copyright
#    notice, this list of conditions and the following disclaimer.
# 2. Redistributions in binary form must reproduce the above copyright
#    notice, this list of conditions and the following disclaimer in the
#    documentation and/or other materials provided with the distribution.
#
# THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR
# IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
# OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
# IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT,
# INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
# NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
# DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
# THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
# (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF
# THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
#
# Copyright (c) 1996 The NetBSD Foundation, Inc.
# All rights reserved.
#
# This code is derived from software contributed to The NetBSD Foundation
# by Jason R. Thorpe.
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions
# are met:
# 1. Redistributions of source code must retain the above copyright
#    notice, this list of conditions and the following disclaimer.
# 2. Redistributions in binary form must reproduce the above copyright
#    notice, this list of conditions and the following disclaimer in the
#    documentation and/or other materials provided with the distribution.
#
# THIS SOFTWARE IS PROVIDED BY THE NETBSD FOUNDATION, INC. AND CONTRIBUTORS
# ``AS IS'' AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED
# TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
# PURPOSE ARE DISCLAIMED.  IN NO EVENT SHALL THE REGENTS OR CONTRIBUTORS BE
# LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
# CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
# SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
# INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
# CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
# ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
# POSSIBILITY OF SUCH DAMAGE.

# Test the first argument against the remaining ones, return success on a match.
isin() {
	local _a=$1 _b

	shift
	for _b; do
		[[ $_a == "$_b" ]] && return 0
	done
	return 1
}

# Add first argument to list formed by the remaining arguments.
# Adds to the tail if the element does not already exist.
addel() {
	local _a=$1

	shift
	isin "$_a" $* && echo -n "$*" || echo -n "${*:+$* }$_a"
}

# Remove all occurrences of first argument from list formed by the remaining
# arguments.
rmel() {
	local _a=$1 _b _c

	shift
	for _b; do
		[[ $_a != "$_b" ]] && _c="${_c:+$_c }$_b"
	done
	echo -n "$_c"
}

# Prints the supplied parameters properly escaped for future sh/ksh parsing.
# Quotes are added if needed, so you should not do that yourself.
quote() (
	# Since this is a subshell we won't pollute the calling namespace.
	for _a; do
		alias Q=$_a; _a=$(alias Q); printf '%s' " ${_a#Q=}"
	done | sed '1s/ //'
	echo
)

# Show a list (passed via ordered arguments) in column output using ls.
show_cols() {
	local _l _cdir=/tmp/i/cdir _clist

	# TODO fix nasty dir usage. be side-effect free!
	mkdir -p $_cdir
	rm -rf -- $_cdir/*
	while read _l; do
		[[ -n $_l ]] || continue
		mkdir -p /tmp/i/cdir/"$_l"
		_clist[${#_clist[*]}]="$_l"
	done
	(cd $_cdir; ls -Cdf "${_clist[@]}")
	rm -rf -- $_cdir
}

# Show list of available things and let the user select some of them.
# Set $resp to list of selected things.
#
# Parameters:
#
# $1 = plural name of the thing we're selecting
# $1 = available things
# $2 = initially selected things
#
select_list() {
	local whats=$1 avail=$2 selected=$3 f action col=$COLUMNS

	# account for 4*2 spaces from '[X] ', +8 from tab
	let COLUMNS=col-16

	cat <<EOF

Select $whats by entering a single name, a glob pattern, or 'all'. De-select
$whats by prepending a '-', e.g. '-foo*'. Selected $whats are labelled '[X]'.
EOF
	while :; do
		for x in $avail; do
			isin "$x" $selected && echo "[X] $x" || echo "[ ] $x"
		done | show_cols | sed 's/^/	/'
		ask "$1 name(s)? (or 'abort' or 'done')" "done"

		set -o noglob
		for resp in $resp; do
			case $resp in
			abort)	selected=; break 2;;
			done)	break 2;;
			-*)	action=rmel;;
			*)	action=addel;;
			esac
			resp=${resp#[+-]}
			[[ $resp == all ]] && resp=*

			for x in $avail; do
				[[ $x == $resp ]] &&
					selected=$($action $x $selected)
			done
		done
	done

	set +o noglob
	COLUMNS=$col

	resp=$selected
}

### End of things from OpenBSD install.sub

ask() {
	echo -n "$1 ${2:+[$2]} "
	read resp
	: ${resp:=$2}
}

askyn() {
	echo -n "$1 [$2] "
	read resp
	: ${resp:=$2}
	case $resp in
	y*)
		return 0
		;;
	esac
	return 1
}

asky() {
	if [ -n "$dash_y" ]; then
		return 0
	else
		askyn "$1" yes
	fi
}

askn() {
	askyn "$1" no
}

warn() {
	echo "${0##*/}: $*" >&2
}

err() {
	warn "$@"
	exit 1
}

vcmd() {
	local green cmd
	if [ X"$1" = X--green ]; then
		green=1
		shift
	fi
	while [ $# -gt 0 ]; do
		cmd="${cmd:+$cmd }$(quote "$1")"
		shift
	done
	qvm-run ${green:+--color-stderr=32} -p "$dom" -- "$cmd"
}

get_vm_info() ( # subshell to scope vars and pipefail
	py='
import sys
import xml.sax

vms = {}

class handler(xml.sax.ContentHandler):
    def startElement(self, name, attrs):
        if name != "QubesVmCollection":
            def qid_or_none(attr):
                if attr in attrs and attrs[attr] != "none":
                    return attrs[attr]
                return None

            vms[attrs["qid"]] = {
                "type": name,
                "name": attrs["name"],
                "label": attrs["label"],
                "netvm": qid_or_none("netvm_qid"),
                "template": qid_or_none("template_qid")
            }

parser = xml.sax.make_parser()
parser.setContentHandler(handler())
parser.parse(open(sys.argv[1], "r"))

def resolve(qid):
    if qid in vms:
        return vms[qid]["name"]
    return ""

for vm in vms.values():
    if vm["type"] == "QubesAppVm":
	print("\t".join([
            vm["name"],
            vm["label"],
            resolve(vm["netvm"]),
            resolve(vm["template"])]))
'

	vm_pat='[A-Za-z][-0-9A-Za-z]*'
	label_pat='[a-z]+'
	exp="${vm_pat}\t${label_pat}(\t(|${vm_pat})){2}"

	# pipefail to bail on errors from within VM or if grep is empty,
	# grep -x to sanitize stdout from VM. vcmd escapes stderr

	set -o pipefail
	vcmd /usr/bin/env python - "${vlq}/qubes.xml" <<< "$py" \
	  | grep -xP "${exp}" | sort
)

# XXX currently unused
fw_rules() {
	vcmd /usr/bin/env python -- "${vlq}" <<EOF
import sys
import xml.sax

class handler(xml.sax.ContentHandler):
    def startElement(self, name, attrs):
        if name == "QubesFirewallRules":
            if attrs["policy"] != "deny":
                raise ValueError("Unimplemented firewall semantics")
            if attrs["dns"] == "allow":
                pass
                # this doesn't work. bug in qvm-firewall?
                #print("accept\t\t\t\tdns")
            if attrs["icmp"] == "allow":
                pass
                # this doesn't work. bug in qvm-firewall?
                #print("accept\t\ticmp")
        if name == "rule":
            addr = attrs["address"]
            if "netmask" in attrs:
                addr += "/"+attrs["netmask"]
            proto = attrs["proto"]
            port = attrs["port"]
            print("\t".join(["accept", addr, proto, port]))

parser = xml.sax.make_parser()
parser.setContentHandler(handler())
parser.parse(open(sys.argv[0], "r"))
EOF
}

yell() {
	printf '\x1b[43m%s\x1b[0m\n' "$*"
}

default_netvm=$(qubes-prefs default_netvm)
default_template=$(qubes-prefs default_template)

map_template() {
	{ [ -n "$tmap" ] && cat "$tmap"; printf '%s\t%s\n' "$1" "$1"; } \
	| grep -m 1 -F "$1	" | cut -f 2
}

import() {
	local old_name old_label old_netvm old_template
	local new_name new_label new_netvm new_template
	local name_changed label_changed netvm_changed template_changed

	old_name=$1
	old_label=$2
	old_netvm=$3
	old_template=${4:-$default_template}

	new_name=$old_name
	new_label=$old_label
	new_netvm=$old_netvm
	new_template=$(map_template "$old_template")

	echo
	while :; do
		### validate name
		while :; do
		       	( ! grep -q -e '[^-0-9A-Za-z]' -e '^[-0-9]' <<< "$new_name" \
				|| { yell "Illegal VM name!"; return 1; } \
			) && ( ! qvm-check -q "$new_name" >/dev/null 2>&1 \
				|| { yell "\"$new_name\" already exists!"; return 1; } \
			) && break
			echo -n "Choose a new name, or enter to skip this VM: "
			read new_name
			[ -n "$new_name" ] || return 1
		done

		### validate label
		case "$new_label" in
		red|orange|yellow|green|gray|blue|purple|black) ;;
		# TODO: dynamically enumerate valid labels instead, since it
		# may be possible to create custom labels in R4 in the future.
		*)
			yell "$old_name: Label \"$new_label\" unknown, using red instead!"
			new_label=red
			;;
		esac

		### validate netvm
		if [ -n "$new_netvm" ] && ! qvm-check -q "$new_netvm" >/dev/null 2>&1; then
			yell "$old_name: NetVM \"$new_netvm\" does not exist, defaulting to $default_netvm!"
			new_netvm=$default_netvm
		fi

		### validate template
		if ! qvm-check -q "$new_template" >/dev/null 2>&1; then
			yell "$old_name: Template \"$new_template\" does not exist, defaulting to $default_template!"
			new_template=$default_template
		fi

		### mark which variables changed
		#for var in name label netvm template; do
		#	eval $var'_changed=$([ X"$old_'$var'" != X"$new_'$var'" ] && echo 1)'
		#done
		# actually, eval is scary, just duplicate code instead...
		    name_changed=$([ X"$old_name"     != X"$new_name"     ] && echo 1)
		   label_changed=$([ X"$old_label"    != X"$new_label"    ] && echo 1)
		   netvm_changed=$([ X"$old_netvm"    != X"$new_netvm"    ] && echo 1)
		template_changed=$([ X"$old_template" != X"$new_template" ] && echo 1)

		### confirm with user
		echo "Going to import ${name_changed:+$old_name (original name) as }$new_name${name_changed:+ (new name)}"
		echo "	label: $new_label${label_changed:+ (originally $old_label)}"
		echo "	netvm: ${new_netvm:-[None]}${netvm_changed:+ (originally $old_netvm)}"
		echo "	template: $new_template${template_changed:+ (originally $old_template)}"
		asky "Create $new_name with these settings?" && break

		### allow editing
		while :; do
			local edit
			echo
			echo "Enter a property (name, label, netvm, template) to change,"
			ask "or \"skip\" to proceed to next VM:" skip

			case "$resp" in
			skip)	return 1 ;;
			na*)	edit=name ;;
			l*)	edit=label ;;
			ne*)	edit=netvm ;;
			t*)	edit=template ;;
			*)	continue ;;
			esac

			echo -n "New $edit: "
			read new_$edit
			break
		done
	done

	### do import
	# find private disk
	local untrusted_old_pimg_path
	untrusted_old_pimg_path=$(vcmd find -L "$vlq" -mindepth 3 -maxdepth 3 -path '*/'"$old_name"'/private.img') \
	  || { yell "Failed to find private.img, skipping VM!"; return 1; }
	# echo -n "path: "; cat -v <<< "$untrusted_old_pimg_path"

	# get it's size
	local untrusted_old_pimg_size old_pimg_size
	untrusted_old_pimg_size=$(vcmd stat -c '%s' "$untrusted_old_pimg_path") \
	  || { yell "Failed to get size for private.img, skipping VM!"; return 1; }
	old_pimg_size=$(tr -dc '[0-9]' <<< "$untrusted_old_pimg_size")
	# echo "size: $old_pimg_size"

	# create the new VM
	qvm-create --label "$new_label" --template "$new_template" -- "$new_name" \
	  || { yell "Error creating $new_name, skipping VM!"; return 1; }

	# create correctly-sized lvm partition
	local vol=private
	local dev
	if ! dev=$(sudo python3 -c '
import sys, qubes
dom, vol, size = sys.argv[1:]
priv = qubes.Qubes().domains[dom].volumes[vol]
priv.resize(int(size))
print(priv.import_data())
	' "$new_name" "$vol" "$old_pimg_size"); then
		yell "Error creating volume for $new_name, cleaning up..."
		qvm-remove -- "$new_name"
		return 1
	fi
	# echo "local dev: $dev"

	local success
	if ( set -o pipefail
	    vcmd --green curl -o- "file://$untrusted_old_pimg_path" \
	      | sudo dd of="$dev" conv=sparse,nocreat status=none
	); then
		success=True
	else
		success=False
		yell "Error copying volume for $new_name, cleaning up..."
	fi

	sudo python3 -c '
import sys, qubes
dom, vol, success = sys.argv[1:]
qubes.Qubes().domains[dom].volumes[vol].import_data_end(bool(success))
	' "$new_name" "$vol" $success || { yell "Cleanup of $dev failed!"; }

	if [ $success = False ]; then
		qvm-remove -- "$new_name"
		return 1
	fi

	if [ X"$new_netvm" != X"$default_netvm" ]; then
		qvm-prefs "$new_name" netvm "$new_netvm" \
		  || { yell "Unable to set netvm to $new_netvm"; }
	fi

	echo "Imported ${name_changed:+$old_name => }$new_name!"
}

import_selected() {
	local name label netvm template _
	local manifest=$1 selected=$2
	for ln in $(tr '\t' , < "$manifest"); do
		IFS=, read name label netvm template _ <<< "$ln"
		if isin "$name" $selected; then
			import "$name" "$label" "$netvm" "$template"
		fi
	done
}

echo "Enumerating VMs available from $dom:$vlq..."
tmpdir=$(mktemp -d) # TODO: trap and clean up
[ -d "$tmpdir" ] || err Unable to make temporary directory
manifest=$tmpdir/qubes-r3-import
get_vm_info > "$manifest" || err "Unable to get VM info from $dom:$vlq"

echo "Checking which VMs we alreay have..."
vm_list_all=$(cut -f 1 < "$manifest")
vm_list_default=$vm_list_all
for vm in $(qvm-ls --fields name --raw-data | grep -xv NAME); do
	vm_list_default=$(rmel "$vm" $vm_list_default)
done

select_list VMs "$vm_list_all" "$vm_list_default"
selected=$resp
import_selected "$manifest" "$selected"
rm "$manifest"
