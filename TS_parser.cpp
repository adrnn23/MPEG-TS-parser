#include "tsCommon.h"
#include "tsTransportStream.h"
#include <cstdio>
#include <iostream>
using namespace std;

//=============================================================================================================================================================================

int main(int argc, char* argv[], char* envp[]) {

	FILE* fp = fopen("/input.ts", "rb");
	FILE* outputFile = fopen("/output.mp2", "wb");

	if (!fp || !outputFile) {
		cerr << "File opening failed" << endl;
		return 1;
	}

	xTS_PacketHeader TS_PacketHeader;
	xTS_AF xTS_AF;
	xPES_PacketHeader xPES_H;
	xPES_Packet xPES_Packet;

	int32_t TS_PacketId = 0;
	uint8_t buffor[188];
	int AFL = 0;
	int offset = 0;

	while (!feof(fp)) {
		fread(buffor, 188, 1, fp);

		TS_PacketHeader.Parse(buffor);
		printf("%010d ", TS_PacketId);
		TS_PacketHeader.Print();

		AFL = 0;
		offset = 0;

		if (TS_PacketHeader.hasAdaptationField) {
			xTS_AF.Parse(buffor);
			AFL = xTS_AF.getAFL();
			offset = 4 + xTS_AF.getAFL();
			//xTS_AF.Print();
		}
		else {
			offset = 4;
		}

		if (TS_PacketHeader.getS() == 1 && TS_PacketHeader.getPID() == 136) {
			xPES_H.Parse(buffor, AFL);
			offset += xPES_H.get_header_length();
			//xPES_H.Print();
			xPES_Packet.state = xPES_Packet::State::Started;
			xPES_Packet.Update(TS_PacketHeader.getCC());
			xPES_Packet.appendPacket(xPES_Packet.getState(), buffor, offset, outputFile);
			xPES_Packet.started = true;
			//xPES_Packet.printState();
		}

		if (TS_PacketHeader.getS() == 0 && TS_PacketHeader.getPID() == 136) {
			xPES_Packet.state = xPES_Packet::State::Continue;
			xPES_Packet.Update(TS_PacketHeader.getCC());
			xPES_Packet.appendPacket(xPES_Packet.getState(), buffor, offset, outputFile);
			//xPES_Packet.printState();
		}

		cout << endl;
		TS_PacketHeader.Reset();
		xTS_AF.Reset();
		xPES_H.Reset();
		TS_PacketId++;
	}

	fclose(fp);
	fclose(outputFile);
	return EXIT_SUCCESS;
}
//=============================================================================================================================================================================