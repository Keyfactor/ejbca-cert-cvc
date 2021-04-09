package org.ejbca.cvc;

import org.bouncycastle.util.encoders.Hex;

public class UnknownAccessRights implements AccessRights
{
    private final byte[] bytes;
    
    public UnknownAccessRights( byte[] bytes )
    {
        this.bytes = bytes;
    }

    @Override
    public byte[] getEncoded()
    {
        return bytes;
    }

    @Override
    public String name()
    {
        return "UNKNOWN";
    }
    
    @Override
    public String toString()
    {
        return "UnknownAccessRights(" + Hex.toHexString( bytes ).toUpperCase() + ")";
    }
}
