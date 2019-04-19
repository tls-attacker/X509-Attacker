package de.rub.nds.asn1.parser;

import de.rub.nds.asn1.TagClass;
import de.rub.nds.asn1.TagConstructed;
import de.rub.nds.asn1.TagNumber;
import de.rub.nds.asn1.parser.contentunpackers.ContentUnpacker;
import de.rub.nds.asn1.parser.contentunpackers.DefaultContentUnpacker;
import de.rub.nds.asn1.parser.contentunpackers.PrimitiveBitStringUnpacker;

/**
 * The content descriptor table contains entries for those ASN.1 fields such as sequence, set, bit string, and octet
 * string that may contain children. Fields that may not contain children are excluded from the table.
 */
public class ContentDescriptorTable {

    private static final ContentDescriptor DEFAULT_CONTENT_DESCRIPTOR = new ContentDescriptor(0, false, 0, false, new DefaultContentUnpacker());

    private static final ContentDescriptor[] contentDescriptors = new ContentDescriptor[]{
            new ContentDescriptor(TagClass.UNIVERSAL, TagConstructed.CONSTRUCTED, TagNumber.BIT_STRING, true, new DefaultContentUnpacker()),
            new ContentDescriptor(TagClass.UNIVERSAL, TagConstructed.CONSTRUCTED, TagNumber.IA5STRING, true, new DefaultContentUnpacker()),
            new ContentDescriptor(TagClass.UNIVERSAL, TagConstructed.CONSTRUCTED, TagNumber.OCTET_STRING, true, new DefaultContentUnpacker()),
            new ContentDescriptor(TagClass.UNIVERSAL, TagConstructed.CONSTRUCTED, TagNumber.PRINTABLESTRING, true, new DefaultContentUnpacker()),
            new ContentDescriptor(TagClass.UNIVERSAL, TagConstructed.CONSTRUCTED, TagNumber.T61STRING, true, new DefaultContentUnpacker()),
            new ContentDescriptor(TagClass.UNIVERSAL, TagConstructed.CONSTRUCTED, TagNumber.UTCTIME, true, new DefaultContentUnpacker()),
            new ContentDescriptor(TagClass.UNIVERSAL, TagConstructed.CONSTRUCTED, TagNumber.UTF8STRING, true, new DefaultContentUnpacker()),
            new ContentDescriptor(TagClass.UNIVERSAL, TagConstructed.PRIMITIVE, TagNumber.BIT_STRING, false, new PrimitiveBitStringUnpacker()),
            new ContentDescriptor(TagClass.UNIVERSAL, TagConstructed.PRIMITIVE, TagNumber.OCTET_STRING, false, new DefaultContentUnpacker()),
            new ContentDescriptor(TagClass.UNIVERSAL, TagConstructed.CONSTRUCTED, TagNumber.SEQUENCE, true, new DefaultContentUnpacker()),
            new ContentDescriptor(TagClass.UNIVERSAL, TagConstructed.CONSTRUCTED, TagNumber.SET, true, new DefaultContentUnpacker())
    };

    public static class ContentDescriptor {

        public final int tagClass;

        public final boolean isConstructed;

        public final int tagNumber;

        public final boolean mustContainValidChildren;

        public final ContentUnpacker contentUnpacker;

        public ContentDescriptor(final int tagClass, final boolean isConstructed, final int tagNumber, final boolean mustContainValidChildren, final ContentUnpacker contentUnpacker) {
            this.tagClass = tagClass;
            this.isConstructed = isConstructed;
            this.tagNumber = tagNumber;
            this.mustContainValidChildren = mustContainValidChildren;
            this.contentUnpacker = contentUnpacker;
        }

        public ContentDescriptor(final TagClass tagClass, final TagConstructed tagConstructed, final TagNumber tagNumber, final boolean mustContainValidChildren, final ContentUnpacker contentUnpacker) {
            this(tagClass.getIntValue(), tagConstructed.getBooleanValue(), tagNumber.getIntValue(), mustContainValidChildren, contentUnpacker);
        }

        @Override
        public boolean equals(Object object) {
            boolean result = true;
            if (object instanceof ContentDescriptor) {
                ContentDescriptor contentDescriptor = (ContentDescriptor) object;
                if (this.tagClass != contentDescriptor.tagClass)
                    result = false;
                if (this.isConstructed != contentDescriptor.isConstructed)
                    result = false;
                if (this.tagNumber != contentDescriptor.tagNumber)
                    result = false;
            } else {
                result = false;
            }
            return result;
        }

        public static ContentDescriptor fromIdentifier(final int tagClass, final boolean isConstructed, final int tagNumber) {
            return new ContentDescriptor(tagClass, isConstructed, tagNumber, false, null);
        }
    }

    public static ContentDescriptor getContentDescriptorForIdentifier(int tagClass, boolean isConstructed, int tagNumber) {
        ContentDescriptor result = DEFAULT_CONTENT_DESCRIPTOR;
        ContentDescriptor compareContentDescriptor = ContentDescriptor.fromIdentifier(tagClass, isConstructed, tagNumber);
        for (ContentDescriptor contentDescriptor : contentDescriptors) {
            if (contentDescriptor.equals(compareContentDescriptor)) {
                result = contentDescriptor;
                break;
            }
        }
        return result;
    }
}
