# makefst
CDN FST packer and packager for Wii U homebrew

## Usage
```
$ makefst [args] [folder]
Option          Parameter           Explanation
-help                               Display this text
-verbose                            Verbose printout
-rawout        "out folder/"        Specify output folder
-raw                                Do not pack FST contents
-noraw                              Remove FST contents when done

Woomy options:
-out           "out name.woomy"     Specify output filename
-append                             Append additional data to existing woomy
-icon          "icon name.tga"      Set metadata icon
-name          "display name"       Set metadata display name
-internal      "internal name"      Set metadata entry name
-entry         "entry path/"        Set entry archive path
```

