Updates for Generation 3 Arcades, built after 03.01.2025

Changelog 11.1.3

--------------------------------------------------

Updates to manage_storage.py

	* Added: "Finalize All Actions" option to the appropriate menus.
	* Added: "Choose Another System to Edit" option to the appropriate menus.
	* Updated: Editable systems now reference system_limit_list.txt in the master lists folder.
	* Added: Checks if a dependencies.txt file exists in the extracted update package directory

--------------------------------------------------

General Changes

	* Updated: Main menus now feature a refreshed QR code.
	* Added: Debug flag for all custom scripts (disabled by default; enable for troubleshooting).
	* Implemented: Save State feature – users can now save and load game states via the Save States menu.
	* Modified: RetroArch now launches in full-screen mode at 1080p resolution, even on 4K TVs.
	* Updated: autostart.sh now includes the --no-splash parameter, removing the EmulationStation loading progress bar on first startup.

	Bug Fixes:
		- Fixed: "Terminated" message when restarting EmulationStation.
		- Fixed: Cursor appearing at startup.
		- Fixed: Suppressed unwanted console outputs (login messages, Raspbian warnings, etc.) to ensure a seamless EmulationStation transition.
		- Fixed: Manage Saves now properly deletes save files—even when the ROM name contains single quotes. (Note: Further investigation is needed for other special characters.)
		- Fixed: Saving issues with PSX memory card files (.srm) have been resolved by switching to the DUCKSTATION core.
		- Fixed: Adjusted QR code and helper image sizes and spacing in the menu.
		- Fixed: Launching from the SaveState system no longer prevents saving new games.
		- Fixed: Saving over an existing save state now updates gamelist.xml with the correct time/date stamp.

	New Features and Additions:
		- Added: New higher resolution helper icons for both system and game browse menus.
		- Added: Manage Saves configuration option for deleting save files.
		- Added: New icon and logo for the Save States menu.
		- Updated: es_systems.cfg:
			* The old RetroPie listing now appears as "Settings."
			* A new folder at /opt/retropie/configs/all/emulationstation/gamelists/settings replaces the old RetroPie gamelist.
		- Added: New informative loading/game launch videos that play randomly via the onstart.sh script.
		- Added: Option to disable informative loading videos in favor of a plain loading video (Settings > Theme Options).

--------------------------------------------------

Security & System Enhancements

	* Updated: Default ROOT password changed from "Pre012or!" to "konamicode."
	* Modified: onstart and onend scripts now bypass loading/exit videos when launching a game from the Settings menu.

	New Additions:
		- Added: Vintage Vault game downloader to fetch games.
		- Added: Manage Storage menu for deleting unwanted games and freeing up space.
		- Added: How-To videos in the User Resources menu under the Settings system, offering tutorials on arcade functionality.
		- Added: Intro video logic that plays an introductory video on first boot if the first_boot_completed flag is missing from the custom_scripts directory.
		- Added: Manage Saves feature fully integrated into working scripts and gamelist.xml under EmulationStation’s Settings menu.
		- Added: Dedicated post-delete video that plays after savegames are deleted, while EmulationStation restarts smoothly. (Separate from the video that plays during save creation.)
			* Updated: Control tester now operates at a higher FPS for improved responsiveness.
			* Added: Welcome messages across all scripts within the Settings menu.
		- Added: Lightgun Support:
			* Implemented support with a dedicated, hidden Lightgun Settings menu (remains hidden in KIOSK mode).
			* Created logic to handle cases when a lightgun is not connected—plays an informative video and exits.
			* Automatically starts lightgun-specific programs when launching a lightgun game.
		- Changed: Replaced the global scanline file with a more visually appealing version.
			* Added .glslp files for all MAME vertical games to apply a vertical scanline, reducing visual artifacts.
		- Improved: Performance enhancements for Dreamcast, Naomi, and Atomiswave systems.
		- Updated: Screensaver settings now handle missing .conf files correctly.
		- Added: Factory default option in arcade setup to restore factory settings.
		- Added: Setup wizard and first-boot video.
		- Added: Dedicated ES WiFi tool rebranded to remove RetroPie references.
		- Implemented: Activate Copy Protection option in arcade configuration. Once activated, the Raspberry Pi is tied to the SD card and will shred all programs          upon tampering.
		- Changed: Samba share now includes only ROMs and Music directories.
		- Changed: HOST name for samba shares updated to simplearcade (previously \\retropie).
		- Added: Delete List, Dependencies & Installation functions to Update System and Wizard Update
