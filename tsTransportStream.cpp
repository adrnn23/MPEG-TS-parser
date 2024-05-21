#include "tsTransportStream.h"
#include <iostream>
using namespace std;
//=============================================================================================================================================================================
// xTS_PacketHeader
//=============================================================================================================================================================================


//Reset - reset all TS packet header fields
void xTS_PacketHeader::Reset() {
	m_SB = 0;
	m_E = 0;
	m_S = 0;
	m_P = 0;
	m_PID = 0;
	m_TSC = 0;
	m_AFC = 0;
	m_CC = 0;
	hasAdaptationField = false;
}

int32_t xTS_PacketHeader::Parse(const uint8_t* Input) {
	uint32_t swapedInput = *((uint32_t*)Input);
	swapedInput = xSwapBytes32(swapedInput);

	m_SB = (swapedInput >> 24) & 0xFF;
	m_E = (swapedInput >> 23) & 1;
	m_S = (swapedInput >> 22) & 1;
	m_P = (swapedInput >> 21) & 1;
	m_PID = (swapedInput >> 8) & 0x1FFF;
	m_TSC = (swapedInput >> 6) & 0x03;
	m_AFC = (swapedInput >> 4) & 0x03;
	m_CC = swapedInput & 0x0F;

	if (m_AFC == 2 || m_AFC == 3) {
		hasAdaptationField = true;
	}

	return 4; // 4 bytes parsed
}

//Print all TS packet header fields
void xTS_PacketHeader::Print() const {
	cout << "TS: ";
	cout << "SB=" << static_cast<int>(m_SB);
	cout << " E=" << static_cast<int>(m_E);
	cout << " S=" << static_cast<int>(m_S);
	cout << " P=" << static_cast<int>(m_P);
	cout << " PID=" << static_cast<int>(m_PID);
	cout << " TSC=" << static_cast<int>(m_TSC);
	cout << " AFC=" << static_cast<int>(m_AFC);
	cout << " CC=" << static_cast<int>(m_CC);
	/*/if (hasAdaptationField) {
		cout << ", ";
	}
	else {
		cout << endl;
	}*/
	cout << ", ";
}

int32_t xTS_AF::Parse(const uint8_t* Input) {
	m_AdaptationFieldLength = 0;
	uint8_t AFL = *(Input + 4);
	uint8_t AF = *(Input + 5);
	m_AFL = (AFL) & 0b11111111;
	m_DC = (AF >> 7) & 1;
	m_RA = (AF >> 6) & 1;
	m_SP = (AF >> 5) & 1;
	m_PR = (AF >> 4) & 1;
	m_OR = (AF >> 3) & 1;
	m_SF = (AF >> 2) & 1;
	m_TP = (AF >> 1) & 1;
	m_EX = AF & 1;

	m_AdaptationFieldLength += (static_cast<int>(m_AFL) + 1);
	return 2; //2 bytes parsed
}

//Print all TS packet header fields
void xTS_AF::Print() const {
	cout << "AF: ";
	cout << "AFL=" << static_cast<int>(m_AFL);
	cout << " DC=" << static_cast<int>(m_DC);
	cout << " RA=" << static_cast<int>(m_RA);
	cout << " SP=" << static_cast<int>(m_SP);
	cout << " PR=" << static_cast<int>(m_PR);
	cout << " OR=" << static_cast<int>(m_OR);
	cout << " SF=" << static_cast<int>(m_SF);
	cout << " TP=" << static_cast<int>(m_TP);
	cout << " EX=" << static_cast<int>(m_EX) << endl;

}

void xTS_AF::Reset() {
	m_AFL = 0;
	m_DC = 0;
	m_RA = 0;
	m_SP = 0;
	m_PR = 0;
	m_OR = 0;
	m_SF = 0;
	m_TP = 0;
	m_EX = 0;
}

int xTS_AF::getAFL() { return m_AdaptationFieldLength; }

void xPES_PacketHeader::Reset() {
	m_PacketStartCodePrefix = 0;
	m_StreamId = 0;
	m_PacketLength = 0;
	m_Header_Length = 0;
}

int32_t xPES_PacketHeader::Parse(const uint8_t* Input, int AFL) {
	m_PacketStartCodePrefix = *((uint32_t*)(Input + 4 + AFL));
	m_PacketStartCodePrefix = xSwapBytes32(m_PacketStartCodePrefix);
	m_PacketStartCodePrefix = (m_PacketStartCodePrefix >> 8) & 0xFFFFFF;

	uint32_t i_StreamId = *((uint32_t*)(Input + 4 + AFL));
	i_StreamId = xSwapBytes32(i_StreamId);
	i_StreamId = (i_StreamId) & 0xFF;
	m_StreamId = (uint8_t)i_StreamId;

	uint32_t i_PacketLength = *((uint32_t*)(Input + 8 + AFL));
	i_PacketLength = xSwapBytes32(i_PacketLength);
	i_PacketLength = (i_PacketLength >> 16) & 0xFFFF;
	m_PacketLength = (uint16_t)i_PacketLength;

	//ts_header(4), AFL, xPES_header(6), optional field(2), header len(1)
	int pes_HL = 6;
	int offset = 4 + AFL + 6 + 2;

	//PES header length
	m_Header_Length = (*(Input + offset) & 0xFF) + pes_HL + 2 + 1;
	return 6; //6 bytes parsed
}

void xPES_PacketHeader::Print() const {
	cout << "PES: ";
	cout << "PSCP=" << static_cast<int>(m_PacketStartCodePrefix);
	cout << " SID=" << static_cast<int>(m_StreamId);
	cout << " L=" << static_cast<int>(m_PacketLength);
}

void xPES_Packet::Update(int iCC) {
	if (state == xPES_Packet::State::Started) {
		prevCC = iCC;
	}
	else {
		if ((prevCC + 1) % 16 == iCC) {
			prevCC = iCC;
		}
		else {
			prevCC = iCC;
			packetLost = true;
			state = State::PacketLost;
		}
	}
}

void xPES_Packet::appendPacket(State iState, const uint8_t* Input, int offset, FILE* outputFile){
	if (packetLost) {
		buffor->clear();
		packetLost = false;
	}

	if (iState == State::Started && started) {
		fwrite(buffor->data(), 1, buffor->size(), outputFile);
		buffor->clear();
	}

	Input += offset;
	for (int i = 0; i < 188 - offset; i++) {
		buffor->push_back(*(Input + i));
	}
}


void xPES_Packet::printState() {
	switch (state) {
	case State::Started:
		cout << " Started " << endl;
		break;
	case State::Continue:
		cout << " Continue " << endl;
		break;
	case State::Finished:
		cout << " Finished " << endl;
		break;
	case State::PacketLost:
		cout << " Packet lost " << endl;
		break;
	}
}
//=============================================================================================================================================================================