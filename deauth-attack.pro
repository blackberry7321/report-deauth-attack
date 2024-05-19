TEMPLATE = app
CONFIG += console c++17
CONFIG -= app_bundle
CONFIG -= qt
LIBS += -lpcap

SOURCES += \
    mac.cpp \
    main.cpp

HEADERS += \
    mac.h
