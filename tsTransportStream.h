#pragma once
#include "tsCommon.h"
#include <string>
#include <stdio.h>
#include <iostream>
#include <vector>
using namespace std;
/*
MPEG-TS packet:
`        3                   2                   1                   0  `
`      1 0 9 8 7 6 5 4 3 2 1 0 9 8 7 6 5 4 3 2 1 0 9 8 7 6 5 4 3 2 1 0  `
`     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+ `
`   0 |                             Header                            | `
`     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+ `
`   4 |                  Adaptation field + Payload                   | `
`     |                                                               | `
` 184 |                                                               | `
`     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+ `


MPEG-TS packet header:
`        3                   2                   1                   0  `
`      1 0 9 8 7 6 5 4 3 2 1 0 9 8 7 6 5 4 3 2 1 0 9 8 7 6 5 4 3 2 1 0  `
`     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+ `
`   0 |       SB      |E|S|T|           PID           |TSC|AFC|   CC  | `
`     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+ `

Sync byte                    (SB ) :  8 bits
Transport error indicator    (E  ) :  1 bit
Payload unit start indicator (S  ) :  1 bit
Transport priority           (T  ) :  1 bit
Packet Identifier            (PID) : 13 bits
Transport scrambling control (TSC) :  2 bits
Adaptation field control     (AFC) :  2 bits
Continuity counter           (CC ) :  4 bits
*/


//=============================================================================================================================================================================

class xTS
{
public:
  static constexpr uint32_t TS_PacketLength  = 188;
  static constexpr uint32_t TS_HeaderLength  = 4;

  static constexpr uint32_t PES_HeaderLength = 6;

  static constexpr uint32_t BaseClockFrequency_Hz         =    90000; //Hz
  static constexpr uint32_t ExtendedClockFrequency_Hz     = 27000000; //Hz
  static constexpr uint32_t BaseClockFrequency_kHz        =       90; //kHz
  static constexpr uint32_t ExtendedClockFrequency_kHz    =    27000; //kHz
  static constexpr uint32_t BaseToExtendedClockMultiplier =      300;
};

//=============================================================================================================================================================================

class xTS_PacketHeader{
public:
  enum class ePID : uint16_t
  {
    PAT  = 0x0000,
    CAT  = 0x0001,
    TSDT = 0x0002,
    IPMT = 0x0003,
    NIT  = 0x0010, //DVB specific PID
    SDT  = 0x0011, //DVB specific PID
    NuLL = 0x1FFF,
  };

protected:
  //header fields
  uint8_t  m_SB;
  uint8_t  m_E;
  uint8_t  m_S;
  uint8_t  m_P;
  uint16_t  m_PID;
  uint8_t  m_TSC;
  uint8_t  m_AFC;
  uint8_t  m_CC;

public:
  void     Reset();
  int32_t  Parse(const uint8_t* Input);
  void     Print() const;

public:
  uint8_t  getSyncByte() const { return m_SB; }  
  int getS() { return static_cast<int>(m_S); }
  int getPID() { return static_cast<int>(m_PID); }
  int getCC() { return static_cast<int>(m_CC); }

public:
   bool hasAdaptationField = false;
};

class xTS_AF {
protected:
    //header fields
    uint8_t  m_AFL;
    uint8_t  m_DC;
    uint8_t  m_RA;
    uint8_t  m_SP;
    uint8_t  m_PR;
    uint8_t  m_OR;
    uint8_t  m_SF;
    uint8_t  m_TP;
    uint8_t  m_EX;
    int m_AdaptationFieldLength;

public:
    int getAFL();
    void     Reset();
    int32_t  Parse(const uint8_t* Input);
    void     Print() const;
};

class xPES_PacketHeader {
protected:
    uint32_t m_PacketStartCodePrefix;
    uint8_t m_StreamId;
    uint16_t m_PacketLength;
    uint8_t m_Header_Length;
public:
    void Reset();
    int32_t Parse(const uint8_t* Input, int AFL);
    void Print() const;

    uint32_t getPacketStartCodePrefix() const { return m_PacketStartCodePrefix; }
    uint8_t getStreamId() const { return m_StreamId; }
    uint16_t getPacketLength() const { return m_PacketLength; }
    int get_header_length() { return m_Header_Length; }
};

class xPES_Packet{
public:
    enum class State {
        Started, Continue, Finished, PacketLost
    };

    xPES_Packet() {
        prevCC = 0;
        state = State::Started;
        packetLost = false;
        started = false;
    }

    bool packetLost;
    State state;
    vector<uint8_t> buffor[2888];

    int prevCC;
    bool started;
    void Update(int iCC);
    void appendPacket(State iState, const uint8_t* Input, int offset, FILE* outputFile);
    void printState();
    State getState() { return state; }
};

//=============================================================================================================================================================================
