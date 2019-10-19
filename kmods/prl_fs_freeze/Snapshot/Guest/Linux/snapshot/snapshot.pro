TEMPLATE = app
TARGET = prl_snapshot
CONFIG += console guest_tool
CONFIG -= qt

TOOLS_LEVEL=$$PWD/../../../..

!include($$TOOLS_LEVEL/Tools.pri) {
	message("include($$TOOLS_LEVEL/Tools.pri)")
	error("failed to include Tools.pri")
}

SOURCES += snapshot.c
