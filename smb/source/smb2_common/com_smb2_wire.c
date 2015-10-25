//
// COMMONWIRE_SMB2.C -
//
// EBSnet - RTSMB
//
// Copyright EBS Inc. , 2014
// All rights reserved.
// This code may not be redistributed in source or linkable object form
// without the consent of its author.
//
// Module description:
// Handles the parsing of all SMB request packets for the server
//
#include "smbdefs.h"

#ifdef SUPPORT_SMB2   /* exclude rest of file */

#include "com_smb2.h"
#include "com_smb2_wiredefs.h"

//#include "srvcmds.h"
#include "smbread.h"
#include "smbutil.h"
#include "smbpack.h"
#include "smbread.h"

/* Set signing rules on the stream. The message finalize process will sign the outgoing messge. */
void  smb2_stream_set_signing_rule(smb2_stream *pstream, byte  *SigningKey, byte SigningRule)
{
    pstream->SigningKey =SigningKey;
    pstream->SigningRule=SigningRule;
}

/* Start encryption. Called on a stream from the top level dispatch if the session is set up and known to be encrypted.
   Wraps the stream in a buffer with an SMB2 transform header prepended. The message finalize process will encrypt the outgoing messge. */
void  smb2_stream_start_encryption(smb2_stream *pstream)
{
    pstream->EncryptMessage   = TRUE;
    pstream->saved_write_origin = pstream->write_origin;
    /* Request a buffer that can hold pstream->write_buffer_size, if encrypt in place is possible return the passed address, which is just beyond the transform header. The write buffer has padding to contain the header.  */
    pstream->pOutBuf =
    pstream->write_origin =
        RTSmb2_Encryption_Get_Encrypt_Buffer( ((PFBYTE)pstream->saved_write_origin)+RTSMB2_NBSS_TRANSFORM_HEADER_SIZE, pstream->write_buffer_size);  /* SPR - added casting to fix compile error */
}


/* Packs a tranform header with information that is required by the receiver to receive and unpack an encrypted message
    Updates:
        pStream->pOutBuf,  pStream->write_buffer_remaining,  pStream->OutBodySize
    Returns:
        -1   If proceeding would run off the buffer end.
        > 0  The number of bytes appended to the stream.
*/
int cmd_fill_transform_header_smb2 (smb2_stream *pStream, PRTSMB2_TRANSFORM_HEADER pItem)
{
    FILL_PROLOG_TEMPLATE
    pItem->Reserved=0;
    PACK_STRUCT_TO_WIRE(pItem,RTSMB2_TRANSFORM_HEADER,52);
#if (0)
    // HOWTO When structure packing is not availble. Extend this to all messages if necessary  */
    /* If these macros fail we return with -1 */
	RTSMB_PACK_ITEM             (pItem->ProtocolId, 4);
    RTSMB_PACK_ITEM             (pItem->Signature,16);
    RTSMB_PACK_ITEM             (pItem->Nonce,16);
    RTSMB_PACK_DWORD            (pItem->OriginalMessageSize);
	RTSMB_PACK_WORD             (pItem->Reserved);       /* Reserved */
	RTSMB_PACK_WORD             (pItem->EncryptionAlgorithm); /* Encryption algortithm */
	RTSMB_PACK_DDWORD           (pItem->SessionId);           /* SessionID values updated later */
#endif
	FILL_EPILOG_TEMPLATE
}

/* Packs a 64 byte SMB2 header.
    Updates:
        pStream->pOutBuf,  pStream->write_buffer_remaining,  pStream->OutBodySize
    Returns:
        -1   If proceeding would run off the buffer end.
        > 0  The number of bytes appended to the stream.
*/
int cmd_fill_header_smb2 (smb2_stream *pStream, PRTSMB2_HEADER pItem)
{
    FILL_PROLOG_TEMPLATE
    pItem->ProtocolId[0]=0xFE;
    pItem->ProtocolId[1]=(byte) 'S'; pItem->ProtocolId[2]=(byte) 'M'; pItem->ProtocolId[3]=(byte) 'B';
    pItem->StructureSize=64;
    pItem->Reserved = 0;
    /* PACK_STRUCT_TO_WIRE checks if the local variable "size" is large enough to contain the buffer. If not returns -1.
       Otherwise copy the bytes from the structure to the wire, decrease the variable size, and increase the pointer variable buf
       The stream buffer values are offloaded and uploaded by the PROLOG and EPILOG macros . */
    PACK_STRUCT_TO_WIRE(pItem,RTSMB2_HEADER,64);
#if (0)
    // HOWTO When structure packing is not availble. Extend this to all messages if necessary  */
	RTSMB_PACK_ITEM             (pItem->ProtocolId, 4);
	RTSMB_PACK_WORD             (pItem->StructureSize);      // SMB2 header structure size
	RTSMB_PACK_WORD             (pItem->CreditCharge);       // Credit charge zero for 2002
	// Channel sequence/ reserved for SMBV3. DWORD status for 2002
	RTSMB_PACK_DWORD            (pItem->Status_ChannelSequenceReserved);   // Status for 2002 see [MS-ERREF] section 2.3.
	RTSMB_PACK_WORD             (pItem->Command);   // Command is a byte in 1.0 but 2.0 command are all < 255
	RTSMB_PACK_WORD             (pItem->CreditRequest_CreditResponse);  // Credit response
	RTSMB_PACK_DWORD            (pItem->Flags);
	RTSMB_PACK_DWORD            (pItem->NextCommand);
	RTSMB_PACK_DDWORD           (pItem->MessageId);
	RTSMB_PACK_DWORD            (pItem->Reserved);
	RTSMB_PACK_DWORD            (pItem->TreeId);
	RTSMB_PACK_DDWORD           (pItem->SessionId);
	/* 16 bytes of security signature */
	RTSMB_PACK_ITEM             (pItem->Signature, 16);
#endif
	FILL_EPILOG_TEMPLATE
}


/* Unpacks a 64 byte SMB2 header from a buffer.
    Returns:
        -1   If size is too small to contain the header or it is not an SMB2 packet by signature
        > 0  The number of bytes in the header (should be 64)
*/
int cmd_read_header_raw_smb2 (PFVOID origin, PFVOID buf, rtsmb_size size, PRTSMB2_HEADER pHeader)
{
	PFVOID s, e;
	s = buf;
    UNPACK_STRUCT_FR_WIRE(pHeader,RTSMB2_HEADER, 64);
	if (pHeader->ProtocolId[0] != 0xFE)
		return -1;
	if (tc_strncmp ((char *)&pHeader->ProtocolId[1], "SMB", 3) != 0)
		return -1;

	e = buf;
	return (int) PDIFF (e, s);
#if (0)
    // HOWTO When structure packing is not availble. Extend this to all messages if necessary  */
	byte b;
    dword dw;

    UNPACK_STRUCT_FR_WIRE(pHeader,RTSMB2_HEADER,64);

    if (pHeader->ProtocolId[0] != 0xFE || tc_strncmp((char *)&pHeader->ProtocolId[1], "SMB", 3) != 0)
		return -1;


	char string [4];

	s = buf;
	RTSMB_READ_BYTE (&b);
	if (b != 0xFE)
    {
		return -1;
    }
	RTSMB_READ_ITEM (string, 3);
	if (tc_strncmp (string, "SMB", 3) != 0)
    {
		return -1;
    }
	RTSMB_READ_WORD (&pHeader->StructureSize);
	RTSMB_READ_WORD (&pHeader->CreditCharge);
	// Channel sequence/ reserved for SMBV3. DWORD status for 2002
	RTSMB_READ_DWORD((PFDWORD)&pHeader->Status_ChannelSequenceReserved);
	RTSMB_READ_WORD (&pHeader->Command);
	RTSMB_READ_WORD (&pHeader->CreditRequest_CreditResponse);
	RTSMB_READ_DWORD((PFDWORD)&pHeader->Flags);
	RTSMB_READ_DWORD((PFDWORD)&pHeader->NextCommand);
	RTSMB_READ_DDWORD(&pHeader->MessageId);
	RTSMB_READ_DWORD(&dw);       // Reserved
	RTSMB_READ_DWORD ((PFDWORD)&pHeader->TreeId);
	RTSMB_READ_DDWORD (&pHeader->SessionId);
	RTSMB_READ_ITEM (pHeader->Signature, 16);

	e = buf;

	return (int) PDIFF (e, s);
#endif
}

/* Unpacks a 64 byte SMB2 header from a stream.
    Updates:
        pStream->pInBuf,  pStream->read_buffer_remaining
    Returns:
        -1   If read_buffer_remaining is too small to contain the header
        > 0  The number of bytes in the header (should be 64)
*/
int cmd_read_header_smb2(smb2_stream *pStream)
{
int consumed;
READ_PROLOG_TEMPLATE
    e=0; /* So compiler doesn't complain */
    s=e;
    e=s;
    consumed = cmd_read_header_raw_smb2 (origin, buf, size, &pStream->InHdr);
    if (consumed > 0)
    {
        ((PFBYTE)pStream->pInBuf) += consumed;  /* SPR - added casting to fix compile error */
        pStream->read_buffer_remaining -= (rtsmb_size)consumed;
    }
	return consumed;
}

/* Unpacks a 64 byte SMB2 header from a stream.
    Updates:
        pStream->pInBuf,  pStream->read_buffer_remaining
    Returns:
        -1   If read_buffer_remaining is too small to contain the header
        > 0  The number of bytes in the header (should be 64)
*/
int cmd_read_transform_header_smb2(PFVOID origin, PFVOID buf, rtsmb_size size, RTSMB2_TRANSFORM_HEADER *pHeader)
{
	PFVOID s, e;
	s = buf;
    UNPACK_STRUCT_FR_WIRE(pHeader,RTSMB2_TRANSFORM_HEADER, 52);
	if (pHeader->ProtocolId[0] != 0xFD)
		return -1;
	if (tc_strncmp ((char *)&pHeader->ProtocolId[1], "SMB", 3) != 0)
		return -1;

	e = buf;
	return (int) PDIFF (e, s);


}


/* Variable encoding part.
    origin is the starting point
    buff is the current buffer.
    size contains bytes left
    pItem is a void pointer to the item

    return -1 if can't be encoded intot the buffer
    return n, the number of bytes encoded.
*/
int SampleVarEncodeFn(PFVOID origin, PFVOID buf, int size,PFVOID pItem)
{
    return 0;
}

/* Generic routine for decoding variable portions of most MSB2 messgages.

    Takes the packet's data offset fields and data length fileds as arguments.

    Calculates offset on the wire to data (if any)
    Reads padding bytes from the wire if needed.

    Reads bytes into into pStream->ReadBufferParms[0].pBuffer and sets pStream->ReadBufferParms[0].byte_count.

    Returns bytes transfered or -1 if byte count is larger than wire count.

*/
int RtsmbWireVarDecode (smb2_stream *pStream, PFVOID origin, PFVOID buf, rtsmb_size size, dword BufferOffset, dword BufferLength, word StructureSize)
{
PFVOID s=buf;
	if (BufferLength)
    {
        dword OffsetToBuffer = BufferOffset- (dword)(StructureSize+pStream->InHdr.StructureSize-1);
	    if (OffsetToBuffer)
	    {
        dword i;
        byte b;
	        for(i = 0; i < OffsetToBuffer; i++)
            {
                RTSMB_READ_BYTE(&b);
            }
	    }
        if (!pStream->ReadBufferParms[0].pBuffer || BufferLength > pStream->ReadBufferParms[0].byte_count)
            return -1;
        pStream->ReadBufferParms[0].byte_count = BufferLength;
        RTSMB_READ_ITEM  (pStream->ReadBufferParms[0].pBuffer, pStream->ReadBufferParms[0].byte_count);
    }
	return PDIFF (buf, s);
}

int RtsmbWireVarEncode(smb2_stream *pStream, PFVOID origin, PFVOID buf, rtsmb_size size,dword BufferOffset, dword BufferLength, word StructureSize)
{
PFVOID s=buf;
    if (BufferLength)
    {
        dword OffsetToBuffer = BufferOffset-(dword)(StructureSize+pStream->OutHdr.StructureSize-1);
rtp_printf("Var encoding . OffsetToBuffer = %d  BufferOffset = %d  StructureSize = %d pStream->OutHdr.StructureSize = %d\n",
    (int) OffsetToBuffer, (int)BufferOffset, (int)StructureSize, (int)pStream->OutHdr.StructureSize );
        while(OffsetToBuffer-- > 0)
            RTSMB_PACK_BYTE(0);
        if (!pStream->WriteBufferParms[0].pBuffer || BufferLength > pStream->WriteBufferParms[0].byte_count)
            return -1;
        RTSMB_PACK_ITEM (pStream->WriteBufferParms[0].pBuffer, BufferLength);
    }
    return PDIFF (buf, s);
}
int RtsmbWireVarEncodePartTwo(smb2_stream *pStream, PFVOID origin, PFVOID buf, rtsmb_size size,dword BufferOffset, dword BufferLength, dword UsedSize)
{
PFVOID s=buf;
    if (BufferLength)
    {
        dword OffsetToBuffer = BufferOffset-(dword)(UsedSize+pStream->OutHdr.StructureSize-1);
        while(OffsetToBuffer-- > 0)
            RTSMB_PACK_BYTE(0);
        if (BufferLength > pStream->WriteBufferParms[1].byte_count)
            return -1;
        RTSMB_PACK_ITEM (pStream->WriteBufferParms[1].pBuffer, BufferLength);
    }
    return PDIFF (buf, s);
}

#include "../client/clissn.h"
int RtsmbWireEncodeSmb2(smb2_stream *pStream, PFVOID pItem, rtsmb_size FixedSize, pVarEncodeFn_t pVarEncodeFn)
{
    FILL_PROLOG_TEMPLATE
    /* PACK_STRUCT_TO_WIRE checks if the local variable "size" is large enough to contain the buffer. If not returns -1.
       Otherwise copy the bytes from the structure to the wire, decrease the variable size, and increase the pointer variable buf
       The stream buffer values are offloaded and uploaded by the PROLOG and EPILOG macros . */
    if (pStream->pSession && pStream->pSession->psmb2Session)
       pStream->OutHdr.SessionId = pStream->pSession->psmb2Session->SessionId;

    PACK_STRUCT_TO_WIRE(&pStream->OutHdr,RTSMB2_HEADER,64);
    PACK_STRUCT_TO_WIRE(pItem,BLOB,FixedSize);
    if (pVarEncodeFn)
    {
        int var_size;
        var_size = pVarEncodeFn(pStream, origin,buf,size,pItem);
        if (var_size < 0)
            return -1;
        buf=PADD(buf,var_size);
        size -= (rtsmb_size) var_size;
    }

	e = buf;
    if (pStream->PadValue) RTSMB_PACK_PAD_TO(pStream->PadValue);
    consumed = (rtsmb_size)PDIFF (e, s);
    ((PFBYTE)pStream->pOutBuf) += consumed;  /* SPR - added casting to fix compile error */
    pStream->write_buffer_remaining-=consumed;
    pStream->OutBodySize+=consumed;
    if (pStream->SigningKey)
        RTSmb2_Encryption_Sign_message(pStream->OutHdr.Signature,pStream->SigningKey, pStream->SigningRule, pStream->write_origin,consumed);
	return (int) consumed;
}



int RtsmbWireDecodeSmb2(smb2_stream *pStream, PFVOID pItem, rtsmb_size FixedSize, pVarDecodeFn_t pVarDecodeFn)
{
    READ_PROLOG_TEMPLATE

    /* UNPACK_STRUCT_FR_WIRE checks if the local variable "size" is large enough to hold the structure. If not returns -1.
       Otherwise copy the bytes from wire to the structure, decrease the variable size, and increase the pointer variable buf
       The stream buffer values are offloaded and uploaded by the PROLOG and EPILOG macros . */
    UNPACK_STRUCT_FR_WIRE(pItem, BLOB, FixedSize);
    if (pVarDecodeFn)
    {
        int var_size;
        var_size = pVarDecodeFn(pStream, origin,buf,size,pItem);
        if (var_size < 0)
            return -1;
        buf=PADD(buf,var_size);
        size -= (rtsmb_size) var_size;
    }
    {
    int consumed;
	e = buf;
        consumed = PDIFF (e, s);
        ((PFBYTE)pStream->pInBuf) += consumed;  /* SPR - added cast to fix compile error */
        pStream->read_buffer_remaining-=(rtsmb_size)consumed;
//        if (pStream->SigningKey)
//            RTSmb2_Encryption_Sign_message(pStream->OutHdr.Signature,pStream->SigningKey, pStream->SigningRule, pStream->read_origin,consumed);
        return consumed;
    }
}
/*
   Finalize after one or more packets have been encoded.
   Perform encryption if it is enabled
*/
int RtsmbWriteFinalizeSmb2(smb2_stream *pStream,ddword SessionId)
{
	if (pStream->Success)
	{
        if (pStream->EncryptMessage)
        {
            RTSMB2_TRANSFORM_HEADER transform_header;
            int encrypted_size;
            /* Initialize SessionId, Algorithm,ProtocolId, and original size. */
            transform_header.SessionId=SessionId;
            transform_header.EncryptionAlgorithm = SMB2_ENCRYPTION_AES128_CCM;
            transform_header.OriginalMessageSize = pStream->OutBodySize;
            transform_header.ProtocolId[0]= 0xFD;
            transform_header.ProtocolId[1]='S';
            transform_header.ProtocolId[2]='M';
            transform_header.ProtocolId[3]='B';

            /*  Encrypts
                     pStream->OutBodySize bytes from pCtx->write_origin into PADD(pStream->saved_write_origin,RTSMB2_NBSS_TRANSFORM_HEADER_SIZE).
                     pStream->write_buffer_size is the maximum desination buffer size

                    also fills in:
                        transform_header.Signature[16];
                        transform_header.Nonce[16];
            */
            encrypted_size = RTSmb2_Encryption_Encrypt_Buffer(
                PADD(pStream->saved_write_origin,RTSMB2_NBSS_TRANSFORM_HEADER_SIZE),
                pStream->write_buffer_size,
                &transform_header,
                pStream->write_origin,
                pStream->OutBodySize
                );
            if (encrypted_size < 0)
                return -1;
            else
            {
                int transform_size;
                /* Restore the original buffer pointers, and write the transform header if there are no errors. */
                pStream->pOutBuf=pStream->write_origin=pStream->saved_write_origin;
                /* Fill the transform header, RTSmb2_Encryption_Encrypt_Buffer already moved the encrypted data into place just after it. */
                transform_size = cmd_fill_transform_header_smb2 (pStream, &transform_header);
                /* Set the body size so we can send */
                pStream->OutBodySize = (rtsmb_size) (transform_size+encrypted_size);
                pStream->write_buffer_remaining =  pStream->write_buffer_size - pStream->OutBodySize;
            }
        }

    }
    return 0;
}
#endif