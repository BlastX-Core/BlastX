
Debian
====================
This directory contains files used to package blastxd/blastx-qt
for Debian-based Linux systems. If you compile blastxd/blastx-qt yourself, there are some useful files here.

## blastx: URI support ##


blastx-qt.desktop  (Gnome / Open Desktop)
To install:

	sudo desktop-file-install blastx-qt.desktop
	sudo update-desktop-database

If you build yourself, you will either need to modify the paths in
the .desktop file or copy or symlink your blastxqt binary to `/usr/bin`
and the `../../share/pixmaps/blastx128.png` to `/usr/share/pixmaps`

blastx-qt.protocol (KDE)

