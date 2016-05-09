/*************************************************************************
 *                                                                       *
 *  CERT-CVC: EAC 1.11 Card Verifiable Certificate Library               * 
 *                                                                       *
 *  This software is free software; you can redistribute it and/or       *
 *  modify it under the terms of the GNU Lesser General Public           *
 *  License as published by the Free Software Foundation; either         *
 *  version 2.1 of the License, or any later version.                    *
 *                                                                       *
 *  See terms of license at gnu.org.                                     *
 *                                                                       *
 *************************************************************************/
package org.ejbca.cvc;

import java.text.DateFormat;
import java.text.SimpleDateFormat;
import java.util.Calendar;
import java.util.Date;
import java.util.TimeZone;

/**
 * Represents a CVC field of type Date
 * 
 * @author Keijo Kurkinen, Swedish National Police Board
 * @version $Id$
 * 
 */
public class DateField extends AbstractDataField {

    private static final long serialVersionUID = 6092901788235446614L;

    /** The length of the array is always the same */
    private static final int DATE_ARRAY_SIZE = 6;

    /** Time Zone GMT must be used for effective and expiration dates */
    private static final TimeZone GMTTIMEZONE = TimeZone.getTimeZone("GMT");

    /** Date format when returning this object as text */
    private static final DateFormat FORMAT_PRINTABLE = new SimpleDateFormat("yyyy-MM-dd");
    static {
        FORMAT_PRINTABLE.setTimeZone(GMTTIMEZONE);
    }

    private Date date;

    DateField(CVCTagEnum type) {
        super(type);
    }

    /**
     * Constructs a new instance from tag and Date
     * 
     * @param type
     * @param date
     */
    DateField(CVCTagEnum type, Date date) {
        this(type);

        Calendar cal = Calendar.getInstance(GMTTIMEZONE);
        cal.setTimeInMillis(date.getTime());

        // Remove time part
        int year = cal.get(Calendar.YEAR);
        int month = cal.get(Calendar.MONTH);
        int day = cal.get(Calendar.DAY_OF_MONTH);
        cal.clear();
        cal.set(year, month, day);
        this.date = cal.getTime();
    }

    /**
     * Constructs instance by decoding DER-encoded data
     * 
     * @param type
     * @param data
     */
    DateField(CVCTagEnum type, byte[] data) {
        this(type);
        if (data == null || data.length != 6) {
            throw new IllegalArgumentException("data argument must have length 6, was " + (data == null ? 0 : data.length));
        }
        int year = 2000 + data[0] * 10 + data[1];
        int month = data[2] * 10 + data[3] - 1; // Java month index starts with
                                                // 0...
        int day = data[4] * 10 + data[5];
        // Now create a Date instance using the decoded values
        Calendar cal = Calendar.getInstance(GMTTIMEZONE);
        cal.clear();
        if (type == CVCTagEnum.EFFECTIVE_DATE) {
            cal.set(year, month, day, 0, 0, 0);
        } else { // EXPIRE_DATE
            // Validity is inclusive this date, so to make sure that
            // a Date comparison gives the expected result we add a
            // time component
            cal.set(year, month, day, 23, 59, 59);
        }
        date = cal.getTime();
    }

    /**
     * Returns the date
     * 
     * @return
     */
    public Date getDate() {
        return date;
    }

    /**
     * Encodes the date value so that every number in '080407' is stored as an
     * individual byte
     *
     * @return
     */
    @Override
    protected byte[] getEncoded() {
        byte[] dateArr = new byte[DATE_ARRAY_SIZE];

        Calendar cal = Calendar.getInstance(GMTTIMEZONE);
        cal.setTimeInMillis(date.getTime());
        int year = cal.get(Calendar.YEAR) - 2000; // Year is encoded as 08, 09,
                                                  // 10 ...
        int month = cal.get(Calendar.MONTH) + 1; // Month is encoded as 1,2, ...
                                                 // ,12
        int day = cal.get(Calendar.DAY_OF_MONTH);
        dateArr[0] = (byte) (year / 10);
        dateArr[1] = (byte) (year % 10);
        dateArr[2] = (byte) (month / 10);
        dateArr[3] = (byte) (month % 10);
        dateArr[4] = (byte) (day / 10);
        dateArr[5] = (byte) (day % 10);
        return dateArr;
    }

    @Override
    protected String valueAsText() {
        return FORMAT_PRINTABLE.format(date);
    }

}
