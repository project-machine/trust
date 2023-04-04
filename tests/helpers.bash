
MDIR=~/.local/share/machine
BACKUP=~/.local/share/machine.backup

function common_setup {
	export TOP_DIR=$(git rev-parse --show-toplevel)
	export PATH=${TOP_DIR}:$PATH

	MDIR=~/.local/share/machine
	BACKUP=~/.local/share/machine.backup
	if [ -d "$BACKUP" ]; then
		rm -rf "$BACKUP"
	fi
	if [ -d "$MDIR" ]; then
		mv "$MDIR" "$BACKUP"
	fi
}

function common_teardown {
	if [ -d "$MDIR" ]; then
		rm -rf "$MDIR"
	fi
	if [ -d "$BACKUP" ]; then
		mv "$BACKUP" "$MDIR"
	fi
}
