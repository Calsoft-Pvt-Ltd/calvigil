package license

// Comprehensive SPDX license classification database.
// Sources: https://spdx.org/licenses/ (v3.28.0) and https://opensource.org/licenses
//
// Licenses are classified into two categories:
//   - Permissive: allow use in proprietary software without source disclosure
//   - Copyleft:   require derivative works to be distributed under the same or compatible terms
//
// Licenses NOT listed here will be classified as "unknown" and flagged for manual review.
// Non-free restrictive licenses (CC-BY-NC, CC-BY-ND, etc.) are intentionally omitted
// so they trigger the "unknown" review flag.

// permissiveLicenses contains all known permissive SPDX license identifiers.
// These are commercially friendly — no source code disclosure obligations.
var permissiveLicenses = map[string]bool{

	// ── MIT family ──────────────────────────────────────────────────────
	"MIT":                                  true, // OSI + FSF
	"MIT-0":                                true, // FSF
	"MIT-advertising":                      true,
	"MIT-Click":                            true,
	"MIT-CMU":                              true, // OSI
	"MIT-enna":                             true,
	"MIT-feh":                              true,
	"MIT-Festival":                         true,
	"MIT-Khronos-old":                      true,
	"MIT-Modern-Variant":                   true, // FSF
	"MIT-open-group":                       true,
	"MIT-STK":                              true,
	"MIT-testregex":                        true,
	"MIT-Wu":                               true,
	"MITNFA":                               true,
	"X11":                                  true, // OSI
	"X11-distribute-modifications-variant": true,
	"X11-no-permit-persons":                true,
	"X11-swapped":                          true,

	// ── Apache family ──────────────────────────────────────────────────
	"Apache-1.0": true, // OSI
	"Apache-1.1": true, // OSI + FSF
	"Apache-2.0": true, // OSI + FSF

	// ── BSD family ─────────────────────────────────────────────────────
	"0BSD":                                 true, // OSI
	"BSD-1-Clause":                         true, // OSI + FSF
	"BSD-2-Clause":                         true, // OSI + FSF
	"BSD-2-Clause-Darwin":                  true,
	"BSD-2-Clause-first-lines":             true,
	"BSD-2-Clause-Patent":                  true, // OSI + FSF
	"BSD-2-Clause-pkgconf-disclaimer":      true,
	"BSD-2-Clause-Views":                   true,
	"BSD-3-Clause":                         true, // OSI + FSF
	"BSD-3-Clause-acpica":                  true,
	"BSD-3-Clause-Attribution":             true,
	"BSD-3-Clause-Clear":                   true, // OSI
	"BSD-3-Clause-flex":                    true,
	"BSD-3-Clause-HP":                      true,
	"BSD-3-Clause-LBNL":                    true, // OSI + FSF
	"BSD-3-Clause-Modification":            true,
	"BSD-3-Clause-No-Military-License":     true,
	"BSD-3-Clause-No-Nuclear-License":      true,
	"BSD-3-Clause-No-Nuclear-License-2014": true,
	"BSD-3-Clause-No-Nuclear-Warranty":     true,
	"BSD-3-Clause-Open-MPI":                true, // OSI + FSF
	"BSD-3-Clause-Sun":                     true,
	"BSD-3-Clause-Tso":                     true,
	"BSD-4-Clause":                         true, // OSI
	"BSD-4-Clause-Shortened":               true,
	"BSD-4-Clause-UC":                      true,
	"BSD-4.3RENO":                          true,
	"BSD-4.3TAHOE":                         true,
	"BSD-Advertising-Acknowledgement":      true,
	"BSD-Attribution-HPND-disclaimer":      true,
	"BSD-Inferno-Nettverk":                 true,
	"BSD-Mark-Modifications":               true,
	"BSD-Protection":                       true,
	"BSD-Source-beginning-file":            true,
	"BSD-Source-Code":                      true,
	"BSD-Systemics":                        true,
	"BSD-Systemics-W3Works":                true,

	// ── ISC / Curl / Zlib ──────────────────────────────────────────────
	"ISC":                  true, // OSI + FSF
	"ISC-Veillard":         true,
	"curl":                 true,
	"Zlib":                 true, // OSI + FSF
	"zlib-acknowledgement": true,

	// ── Public Domain & Dedications ────────────────────────────────────
	"Unlicense":                    true, // OSI + FSF
	"Unlicense-libtelnet":          true,
	"Unlicense-libwhirlpool":       true,
	"CC0-1.0":                      true, // OSI
	"CC-PDDC":                      true,
	"CC-PDM-1.0":                   true,
	"PDDL-1.0":                     true,
	"SAX-PD":                       true,
	"SAX-PD-2.0":                   true,
	"blessing":                     true,
	"WTFPL":                        true, // OSI
	"GLWTPL":                       true,
	"Fair":                         true, // OSI + FSF
	"FSFAP":                        true, // OSI
	"FSFAP-no-warranty-disclaimer": true,
	"FSFUL":                        true,
	"FSFULLR":                      true,
	"FSFULLRSD":                    true,
	"FSFULLRWD":                    true,

	// ── Creative Commons (permissive — attribution only) ───────────────
	"CC-BY-1.0":     true,
	"CC-BY-2.0":     true,
	"CC-BY-2.5":     true,
	"CC-BY-2.5-AU":  true,
	"CC-BY-3.0":     true,
	"CC-BY-3.0-AT":  true,
	"CC-BY-3.0-AU":  true,
	"CC-BY-3.0-DE":  true,
	"CC-BY-3.0-IGO": true,
	"CC-BY-3.0-NL":  true,
	"CC-BY-3.0-US":  true,
	"CC-BY-4.0":     true, // OSI

	// ── Boost / BSL ────────────────────────────────────────────────────
	"BSL-1.0": true, // OSI + FSF

	// ── Python ─────────────────────────────────────────────────────────
	"Python-2.0":                 true, // OSI + FSF
	"Python-2.0.1":               true,
	"python-ldap":                true,
	"PSF-2.0":                    true,
	"CNRI-Python":                true, // OSI + FSF
	"CNRI-Python-GPL-Compatible": true,
	"CNRI-Jython":                true,

	// ── Academic / Research ────────────────────────────────────────────
	"AAL":                             true, // OSI
	"AFL-1.1":                         true, // OSI + FSF
	"AFL-1.2":                         true, // OSI + FSF
	"AFL-2.0":                         true, // OSI + FSF
	"AFL-2.1":                         true, // OSI + FSF
	"AFL-3.0":                         true, // OSI + FSF
	"Artistic-1.0":                    true, // FSF
	"Artistic-1.0-cl8":                true, // FSF
	"Artistic-1.0-Perl":               true, // FSF
	"Artistic-2.0":                    true, // OSI + FSF
	"Artistic-dist":                   true,
	"CAL-1.0":                         true, // OSI + FSF
	"CAL-1.0-Combined-Work-Exception": true, // OSI + FSF
	"CATOSL-1.1":                      true, // OSI + FSF
	"ECL-1.0":                         true, // OSI + FSF
	"ECL-2.0":                         true, // OSI + FSF
	"EFL-1.0":                         true, // FSF
	"EFL-2.0":                         true, // OSI + FSF
	"Entessa":                         true, // OSI + FSF
	"EUDatagrid":                      true, // OSI + FSF
	"Frameworx-1.0":                   true, // OSI + FSF
	"NCSA":                            true, // OSI + FSF
	"NASA-1.3":                        true, // OSI + FSF
	"NPOSL-3.0":                       true, // FSF
	"NTP":                             true, // OSI + FSF
	"NTP-0":                           true,
	"OGTSL":                           true, // OSI + FSF
	"OSET-PL-2.1":                     true, // OSI + FSF
	"OSC-1.0":                         true, // OSI + FSF
	"OLFL-1.3":                        true, // OSI + FSF

	// ── OpenLDAP ───────────────────────────────────────────────────────
	"OLDAP-1.1":   true,
	"OLDAP-1.2":   true,
	"OLDAP-1.3":   true,
	"OLDAP-1.4":   true,
	"OLDAP-2.0":   true,
	"OLDAP-2.0.1": true,
	"OLDAP-2.1":   true,
	"OLDAP-2.2":   true,
	"OLDAP-2.2.1": true,
	"OLDAP-2.2.2": true,
	"OLDAP-2.3":   true, // OSI
	"OLDAP-2.4":   true,
	"OLDAP-2.5":   true,
	"OLDAP-2.6":   true,
	"OLDAP-2.7":   true, // OSI
	"OLDAP-2.8":   true, // OSI + FSF

	// ── Corporate / Foundation ─────────────────────────────────────────
	"BlueOak-1.0.0":      true, // OSI + FSF
	"PostgreSQL":         true, // OSI + FSF
	"UPL-1.0":            true, // OSI + FSF
	"Unicode-3.0":        true, // OSI + FSF
	"Unicode-DFS-2015":   true,
	"Unicode-DFS-2016":   true, // OSI + FSF
	"Unicode-TOU":        true,
	"OpenSSL":            true, // OSI
	"OpenSSL-standalone": true,
	"SSLeay-standalone":  true,
	"MS-PL":              true, // OSI + FSF
	"MS-RL":              true, // OSI + FSF
	"MulanPSL-1.0":       true,
	"MulanPSL-2.0":       true, // OSI + FSF
	"JSON":               true,
	"FTL":                true, // OSI
	"UCL-1.0":            true, // OSI + FSF
	"WordNet":            true, // OSI + FSF

	// ── PHP / Web ──────────────────────────────────────────────────────
	"PHP-3.0":  true, // OSI + FSF
	"PHP-3.01": true, // OSI + FSF
	"Zend-2.0": true, // OSI
	"Cube":     true,
	"Motosoto": true, // OSI + FSF

	// ── Imaging / Graphics / Fonts ─────────────────────────────────────
	"IJG":                                  true, // OSI
	"IJG-short":                            true,
	"ImageMagick":                          true,
	"Libpng":                               true,
	"libpng-1.6.35":                        true,
	"libpng-2.0":                           true,
	"libtiff":                              true,
	"HPND":                                 true, // OSI + FSF
	"HPND-DEC":                             true,
	"HPND-doc":                             true,
	"HPND-doc-sell":                        true,
	"HPND-export-US":                       true,
	"HPND-export-US-acknowledgement":       true,
	"HPND-export-US-modify":                true,
	"HPND-export2-US":                      true,
	"HPND-Fenneberg-Livingston":            true,
	"HPND-INRIA-IMAG":                      true,
	"HPND-Intel":                           true,
	"HPND-Kevlin-Henney":                   true,
	"HPND-Markus-Kuhn":                     true,
	"HPND-merchantability-variant":         true,
	"HPND-MIT-disclaimer":                  true,
	"HPND-Netrek":                          true,
	"HPND-Pbmplus":                         true,
	"HPND-sell-MIT-disclaimer-xserver":     true,
	"HPND-sell-regexpr":                    true,
	"HPND-sell-variant":                    true,
	"HPND-sell-variant-critical-systems":   true,
	"HPND-sell-variant-MIT-disclaimer":     true,
	"HPND-sell-variant-MIT-disclaimer-rev": true,
	"HPND-SMC":                             true,
	"HPND-UC":                              true,
	"HPND-UC-export-US":                    true,
	"AMPAS":                                true,
	"Beerware":                             true,
	"OFL-1.0":                              true, // OSI
	"OFL-1.0-no-RFN":                       true,
	"OFL-1.1":                              true, // OSI + FSF
	"OFL-1.1-no-RFN":                       true, // FSF
	"OFL-1.1-RFN":                          true, // FSF
	"Pixar":                                true,
	"FreeImage":                            true,
	"GD":                                   true,

	// ── Telecom / Standards / W3C ──────────────────────────────────────
	"ICU":          true, // OSI + FSF
	"W3C":          true, // OSI + FSF
	"W3C-19980720": true,
	"W3C-20150513": true, // OSI + FSF
	"IETF-Trust":   true,

	// ── Hardware / CERN ────────────────────────────────────────────────
	"CERN-OHL-P-2.0": true, // OSI + FSF (permissive variant)

	// ── Data Licenses (permissive) ─────────────────────────────────────
	"CDLA-Permissive-1.0": true,
	"CDLA-Permissive-2.0": true,
	"C-UDA-1.0":           true,
	"O-UDA-1.0":           true,
	"ODbL-1.0":            true, // OSI
	"ODC-By-1.0":          true,
	"DL-DE-BY-2.0":        true,
	"DL-DE-ZERO-2.0":      true,
	"OGL-Canada-2.0":      true,
	"OGL-UK-1.0":          true,
	"OGL-UK-2.0":          true,
	"OGL-UK-3.0":          true,
	"OGDL-Taiwan-1.0":     true,
	"NLOD-1.0":            true,
	"NLOD-2.0":            true,

	// ── Intel / IBM / Sun ──────────────────────────────────────────────
	"Intel":      true, // OSI + FSF
	"Intel-ACPI": true,
	"Info-ZIP":   true,
	"IPA":        true, // OSI + FSF
	"Jam":        true, // OSI + FSF

	// ── Lucent / LPL ───────────────────────────────────────────────────
	"LPL-1.0":  true, // OSI + FSF
	"LPL-1.02": true, // OSI + FSF

	// ── LaTeX ──────────────────────────────────────────────────────────
	"LPPL-1.0":                  true,
	"LPPL-1.1":                  true,
	"LPPL-1.2":                  true, // OSI
	"LPPL-1.3a":                 true, // OSI
	"LPPL-1.3c":                 true, // FSF
	"Latex2e":                   true,
	"Latex2e-translated-notice": true,

	// ── Québec ─────────────────────────────────────────────────────────
	"LiLiQ-P-1.1": true, // OSI + FSF (permissive variant)

	// ── Miscellaneous OSI-approved & FSF-free ──────────────────────────
	"APL-1.0":            true, // OSI + FSF
	"Xnet":               true, // OSI + FSF
	"Xerox":              true,
	"VSL-1.0":            true, // FSF
	"Vim":                true, // OSI
	"Spencer-86":         true,
	"Spencer-94":         true,
	"Spencer-99":         true,
	"Sleepycat":          true, // OSI + FSF
	"SimPL-2.0":          true, // OSI + FSF
	"RSCPL":              true, // OSI + FSF
	"RPL-1.1":            true, // OSI + FSF
	"RPL-1.5":            true, // OSI + FSF
	"Rdisc":              true,
	"QPL-1.0":            true, // OSI + FSF
	"QPL-1.0-INRIA-2004": true,
	"Plexus":             true,
	"OPL-1.0":            true,
	"NGPL":               true, // OSI + FSF
	"Naumen":             true, // OSI + FSF
	"Multics":            true, // OSI + FSF
	"MirOS":              true, // OSI + FSF
	"Leptonica":          true,
	"ClArtistic":         true, // OSI
	"Condor-1.1":         true, // OSI
	"CUA-OPL-1.0":        true, // OSI + FSF
	"DSDP":               true,
	"DOC":                true,
	"diffmark":           true,
	"dvipdfm":            true,
	"FreeBSD-DOC":        true,
	"Giftware":           true,
	"HaskellReport":      true,
	"HTMLTIDY":           true,

	// ── Ruby ───────────────────────────────────────────────────────────
	"Ruby":     true, // OSI
	"Ruby-pty": true,

	// ── Misc well-known ────────────────────────────────────────────────
	"APAFML":                            true,
	"AML":                               true,
	"AML-glslang":                       true,
	"Abstyles":                          true,
	"Adobe-2006":                        true,
	"Adobe-Display-PostScript":          true,
	"Adobe-Glyph":                       true,
	"Adobe-Utopia":                      true,
	"ADSL":                              true,
	"Afmparse":                          true,
	"Aladdin":                           true,
	"ALGLIB-Documentation":              true,
	"ANTLR-PD":                          true,
	"ANTLR-PD-fallback":                 true,
	"Bahyph":                            true,
	"Barr":                              true,
	"Baekmuk":                           true,
	"bcrypt-Solar-Designer":             true,
	"Bitstream-Charter":                 true,
	"Bitstream-Vera":                    true,
	"BitTorrent-1.0":                    true,
	"BitTorrent-1.1":                    true, // OSI
	"Boehm-GC":                          true,
	"Boehm-GC-without-fee":              true,
	"Borceux":                           true,
	"Brian-Gladman-2-Clause":            true,
	"Brian-Gladman-3-Clause":            true,
	"bzip2-1.0.6":                       true,
	"Caldera":                           true,
	"Caldera-no-preamble":               true,
	"Catharon":                          true,
	"CFITSIO":                           true,
	"checkmk":                           true,
	"Clips":                             true,
	"CMU-Mach":                          true,
	"CMU-Mach-nodoc":                    true,
	"COIL-1.0":                          true,
	"Community-Spec-1.0":                true,
	"Cornell-Lossless-JPEG":             true,
	"Cronyx":                            true,
	"Crossword":                         true,
	"CryptoSwift":                       true,
	"CrystalStacker":                    true,
	"DEC-3-Clause":                      true,
	"DocBook-DTD":                       true,
	"DocBook-Schema":                    true,
	"DocBook-Stylesheet":                true,
	"DocBook-XML":                       true,
	"Dotseqn":                           true,
	"dtoa":                              true,
	"eGenix":                            true,
	"EPICS":                             true,
	"ESA-PL-permissive-2.4":             true,
	"etalab-2.0":                        true,
	"Eurosym":                           true,
	"FBM":                               true,
	"FDK-AAC":                           true,
	"Ferguson-Twofish":                  true,
	"Furuseth":                          true,
	"fwlw":                              true,
	"GCR-docs":                          true,
	"generic-xts":                       true,
	"GL2PS":                             true,
	"Glide":                             true,
	"Glulxe":                            true,
	"gnuplot":                           true, // OSI
	"Graphics-Gems":                     true,
	"gSOAP-1.3b":                        true,
	"gtkbook":                           true,
	"Gutmann":                           true,
	"HDF5":                              true,
	"hdparm":                            true,
	"HIDAPI":                            true,
	"HP-1986":                           true,
	"HP-1989":                           true,
	"hyphen-bulgarian":                  true,
	"IBM-pibs":                          true,
	"IEC-Code-Components-EULA":          true,
	"iMatix":                            true, // OSI
	"Imlib2":                            true, // OSI
	"Inner-Net-2.0":                     true,
	"InnoSetup":                         true,
	"Interbase-1.0":                     true,
	"JasPer-2.0":                        true,
	"jove":                              true,
	"JPL-image":                         true,
	"JPNIC":                             true,
	"Kastrup":                           true,
	"Kazlib":                            true,
	"Knuth-CTAN":                        true,
	"libselinux-1.0":                    true,
	"libutil-David-Nugent":              true,
	"Linux-man-pages-1-para":            true,
	"Linux-man-pages-copyleft":          true,
	"Linux-man-pages-copyleft-2-para":   true,
	"Linux-man-pages-copyleft-var":      true,
	"Linux-OpenIB":                      true,
	"LOOP":                              true,
	"LPD-document":                      true,
	"lsof":                              true,
	"Lucida-Bitmap-Fonts":               true,
	"LZMA-SDK-9.11-to-9.20":             true,
	"LZMA-SDK-9.22":                     true,
	"Mackerras-3-Clause":                true,
	"Mackerras-3-Clause-acknowledgment": true,
	"magaz":                             true,
	"mailprio":                          true,
	"MakeIndex":                         true,
	"man2html":                          true,
	"Martin-Birgmeier":                  true,
	"McPhee-slideshow":                  true,
	"metamail":                          true,
	"Minpack":                           true,
	"MIPS":                              true,
	"MMIXware":                          true,
	"MPEG-SSG":                          true,
	"mpi-permissive":                    true,
	"mpich2":                            true,
	"mplus":                             true,
	"MTLL":                              true,
	"Mup":                               true,
	"NAIST-2003":                        true,
	"NBPL-1.0":                          true,
	"NCBI-PD":                           true,
	"NCL":                               true,
	"NetCDF":                            true,
	"Newsletr":                          true,
	"ngrep":                             true,
	"NICTA-1.0":                         true,
	"NIST-PD":                           true,
	"NIST-PD-fallback":                  true,
	"NIST-PD-TNT":                       true,
	"NIST-Software":                     true,
	"NLPL":                              true,
	"NOSL":                              true, // OSI
	"NPL-1.0":                           true, // OSI
	"NPL-1.1":                           true, // OSI
	"NRL":                               true,
	"NTIA-PD":                           true,
	"OAR":                               true,
	"OCLC-2.0":                          true, // OSI + FSF
	"OFFIS":                             true,
	"OML":                               true,
	"OpenMDW-1.0":                       true,
	"OpenPBS-2.3":                       true,
	"OpenVision":                        true,
	"OPUBL-1.0":                         true,
	"OSSP":                              true,
	"PADL":                              true,
	"ParaType-Free-Font-1.3":            true,
	"pkgconf":                           true,
	"pnmstitch":                         true,
	"psfrag":                            true,
	"psutils":                           true,
	"Qhull":                             true,
	"radvd":                             true,
	"RSA-MD":                            true,
	"Saxpath":                           true,
	"SCEA":                              true,
	"SchemeReport":                      true,
	"Sendmail":                          true,
	"Sendmail-8.23":                     true,
	"Sendmail-Open-Source-1.1":          true,
	"SGI-B-1.0":                         true,
	"SGI-B-1.1":                         true,
	"SGI-B-2.0":                         true, // OSI
	"SGI-OpenGL":                        true,
	"SGP4":                              true,
	"SHL-0.5":                           true,
	"SHL-0.51":                          true,
	"SL":                                true,
	"SMLNJ":                             true, // OSI
	"StandardML-NJ":                     true,
	"SMPPL":                             true,
	"SNIA":                              true,
	"snprintf":                          true,
	"SOFA":                              true,
	"softSurfer":                        true,
	"Soundex":                           true,
	"ssh-keyscan":                       true,
	"SSH-OpenSSH":                       true,
	"SSH-short":                         true,
	"SunPro":                            true,
	"Sun-PPP":                           true,
	"Sun-PPP-2000":                      true,
	"SWL":                               true,
	"swrule":                            true,
	"Symlinks":                          true,
	"TCL":                               true,
	"TCP-wrappers":                      true,
	"TekHVC":                            true,
	"TermReadKey":                       true,
	"ThirdEye":                          true,
	"threeparttable":                    true,
	"TMate":                             true,
	"TOML":                              true,
	"TPDL":                              true,
	"TrustedQSL":                        true,
	"TTWL":                              true,
	"TTYP0":                             true,
	"TU-Berlin-1.0":                     true,
	"TU-Berlin-2.0":                     true,
	"Ubuntu-font-1.0":                   true,
	"UCAR":                              true,
	"ulem":                              true,
	"UMich-Merit":                       true,
	"UnixCrypt":                         true,
	"URT-RLE":                           true,
	"Vixie-Cron":                        true,
	"VOSTROM":                           true,
	"w3m":                               true,
	"Widget-Workshop":                   true,
	"Wsuipa":                            true,
	"wwl":                               true,
	"Xdebug-1.03":                       true,
	"Xfig":                              true,
	"XFree86-1.1":                       true, // OSI
	"xinetd":                            true, // OSI
	"xkeyboard-config-Zinoviev":         true,
	"xlock":                             true,
	"xpp":                               true,
	"XSkat":                             true,
	"xzoom":                             true,
	"Zed":                               true,
	"Zeeff":                             true,
	"Zimbra-1.3":                        true, // OSI
	"Zimbra-1.4":                        true,
	"ZPL-1.1":                           true,
	"ZPL-2.0":                           true, // OSI + FSF
	"ZPL-2.1":                           true, // OSI + FSF

	// ── Deprecated SPDX IDs (still seen in the wild) ───────────────────
	"BSD-2-Clause-FreeBSD": true,
	"BSD-2-Clause-NetBSD":  true,
	"bzip2-1.0.5":          true,
	"Net-SNMP":             true,
	"Nunit":                true,
	"wxWindows":            true, // OSI
}

// copyleftLicenses contains all known copyleft/reciprocal SPDX license identifiers.
// These require derivative works to be shared under the same or compatible terms.
var copyleftLicenses = map[string]bool{

	// ── GPL family ─────────────────────────────────────────────────────
	"GPL-1.0-only":     true,
	"GPL-1.0-or-later": true,
	"GPL-2.0":          true, // deprecated alias
	"GPL-2.0-only":     true, // OSI + FSF
	"GPL-2.0-or-later": true, // OSI + FSF
	"GPL-3.0":          true, // deprecated alias
	"GPL-3.0-only":     true, // OSI + FSF
	"GPL-3.0-or-later": true, // OSI + FSF

	// ── AGPL family ────────────────────────────────────────────────────
	"AGPL-1.0":          true, // deprecated alias
	"AGPL-1.0-only":     true,
	"AGPL-1.0-or-later": true,
	"AGPL-3.0":          true, // deprecated alias
	"AGPL-3.0-only":     true, // OSI + FSF
	"AGPL-3.0-or-later": true, // OSI + FSF

	// ── LGPL family (weak copyleft) ────────────────────────────────────
	"LGPL-2.0":          true, // deprecated alias
	"LGPL-2.0-only":     true, // FSF
	"LGPL-2.0-or-later": true, // FSF
	"LGPL-2.1":          true, // deprecated alias
	"LGPL-2.1-only":     true, // OSI + FSF
	"LGPL-2.1-or-later": true, // OSI + FSF
	"LGPL-3.0":          true, // deprecated alias
	"LGPL-3.0-only":     true, // OSI + FSF
	"LGPL-3.0-or-later": true, // OSI + FSF

	// ── MPL (weak copyleft) ────────────────────────────────────────────
	"MPL-1.0":                       true, // OSI + FSF
	"MPL-1.1":                       true, // OSI + FSF
	"MPL-2.0":                       true, // OSI + FSF
	"MPL-2.0-no-copyleft-exception": true, // FSF

	// ── EPL / Eclipse (weak copyleft) ──────────────────────────────────
	"EPL-1.0": true, // OSI + FSF
	"EPL-2.0": true, // OSI + FSF

	// ── CDDL (weak copyleft) ───────────────────────────────────────────
	"CDDL-1.0": true, // OSI + FSF
	"CDDL-1.1": true, // OSI

	// ── EU Licenses ────────────────────────────────────────────────────
	"EUPL-1.0": true,
	"EUPL-1.1": true, // OSI + FSF
	"EUPL-1.2": true, // OSI + FSF

	// ── CeCILL (copyleft variants) ─────────────────────────────────────
	"CECILL-1.0": true,
	"CECILL-1.1": true,
	"CECILL-2.0": true, // OSI
	"CECILL-2.1": true, // OSI + FSF
	"CECILL-B":   true, // OSI
	"CECILL-C":   true, // OSI

	// ── OSL (copyleft) ─────────────────────────────────────────────────
	"OSL-1.0": true, // OSI + FSF
	"OSL-1.1": true, // OSI
	"OSL-2.0": true, // OSI + FSF
	"OSL-2.1": true, // OSI + FSF
	"OSL-3.0": true, // OSI + FSF

	// ── Apple (weak copyleft) ──────────────────────────────────────────
	"APSL-1.0": true, // FSF
	"APSL-1.1": true, // FSF
	"APSL-1.2": true, // FSF
	"APSL-2.0": true, // OSI + FSF

	// ── Other copyleft / reciprocal ────────────────────────────────────
	"CPAL-1.0":   true, // OSI + FSF
	"CPL-1.0":    true, // OSI + FSF
	"IPL-1.0":    true, // OSI + FSF
	"SSPL-1.0":   true,
	"RPSL-1.0":   true, // OSI + FSF
	"SPL-1.0":    true, // OSI + FSF
	"Watcom-1.0": true, // OSI + FSF
	"ErlPL-1.1":  true,
	"Nokia":      true, // OSI + FSF
	"SISSL":      true, // OSI + FSF
	"SISSL-1.2":  true,
	"RHeCos-1.1": true,
	"eCos-2.0":   true, // OSI

	// ── Québec (copyleft variants) ─────────────────────────────────────
	"LiLiQ-R-1.1":     true, // OSI + FSF
	"LiLiQ-Rplus-1.1": true, // OSI + FSF

	// ── CERN Hardware (copyleft variants) ──────────────────────────────
	"CERN-OHL-S-2.0": true, // OSI + FSF (strongly reciprocal)
	"CERN-OHL-W-2.0": true, // OSI + FSF (weakly reciprocal)

	// ── Creative Commons ShareAlike (copyleft) ─────────────────────────
	"CC-BY-SA-1.0":     true,
	"CC-BY-SA-2.0":     true,
	"CC-BY-SA-2.0-UK":  true,
	"CC-BY-SA-2.1-JP":  true,
	"CC-BY-SA-2.5":     true,
	"CC-BY-SA-3.0":     true,
	"CC-BY-SA-3.0-AT":  true,
	"CC-BY-SA-3.0-DE":  true,
	"CC-BY-SA-3.0-IGO": true,
	"CC-BY-SA-4.0":     true, // OSI

	// ── GFDL (documentation copyleft) ──────────────────────────────────
	"GFDL-1.1-only":                   true, // FSF
	"GFDL-1.1-or-later":               true, // FSF
	"GFDL-1.1-invariants-only":        true,
	"GFDL-1.1-invariants-or-later":    true,
	"GFDL-1.1-no-invariants-only":     true,
	"GFDL-1.1-no-invariants-or-later": true,
	"GFDL-1.2-only":                   true, // FSF
	"GFDL-1.2-or-later":               true, // FSF
	"GFDL-1.2-invariants-only":        true,
	"GFDL-1.2-invariants-or-later":    true,
	"GFDL-1.2-no-invariants-only":     true,
	"GFDL-1.2-no-invariants-or-later": true,
	"GFDL-1.3-only":                   true, // FSF
	"GFDL-1.3-or-later":               true, // FSF
	"GFDL-1.3-invariants-only":        true,
	"GFDL-1.3-invariants-or-later":    true,
	"GFDL-1.3-no-invariants-only":     true,
	"GFDL-1.3-no-invariants-or-later": true,

	// ── Other reciprocal / misc ────────────────────────────────────────
	"copyleft-next-0.3.0": true,
	"copyleft-next-0.3.1": true,
	"D-FSL-1.0":           true,
	"LAL-1.2":             true,
	"LAL-1.3":             true,
	"LGPLLR":              true,
	"OCCT-PL":             true,
	"OPL-UK-3.0":          true,
	"Parity-6.0.0":        true,
	"Parity-7.0.0":        true,
	"SMAIL-GPL":           true,
	"CDLA-Sharing-1.0":    true,
	"TOSL":                true,
	"YPL-1.0":             true,
	"YPL-1.1":             true, // OSI
	"SugarCRM-1.1.3":      true,

	// ── Deprecated aliases (still seen in the wild) ────────────────────
	"GPL-2.0+":                         true,
	"GPL-3.0+":                         true,
	"LGPL-2.0+":                        true,
	"LGPL-2.1+":                        true,
	"LGPL-3.0+":                        true,
	"GPL-2.0-with-autoconf-exception":  true,
	"GPL-2.0-with-bison-exception":     true,
	"GPL-2.0-with-classpath-exception": true,
	"GPL-2.0-with-font-exception":      true,
	"GPL-2.0-with-GCC-exception":       true,
	"GPL-3.0-with-autoconf-exception":  true,
	"GPL-3.0-with-GCC-exception":       true,
	"GFDL-1.1":                         true, // deprecated
	"GFDL-1.2":                         true, // deprecated
	"GFDL-1.3":                         true, // deprecated
	"GPL-1.0+":                         true, // deprecated
}
