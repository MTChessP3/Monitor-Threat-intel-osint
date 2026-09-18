// Self-contained Android binary XML (AXML) parser.
// Works in both Node and browser runtimes (DataView based, no Buffer).
// Produces the same document shape as adbkit-apkreader's BinaryXmlParser so the
// analysis engine is runtime-agnostic: { nodeName, attributes[], childNodes[] }.

const CHUNK_STRING_POOL = 0x0001;
const CHUNK_RESOURCE_MAP = 0x0180;
const CHUNK_START_NAMESPACE = 0x0100;
const CHUNK_END_NAMESPACE = 0x0101;
const CHUNK_START_ELEMENT = 0x0102;
const CHUNK_END_ELEMENT = 0x0103;
const CHUNK_CDATA = 0x0104;
const CHUNK_XML = 0x0003;

const STRING_FLAG_UTF8 = 0x00000100;

export interface AxmlAttribute {
  name: string;
  value: string | number | boolean | null;
  typedValue?: { type: string; value: string | number | boolean | null; data: number };
}

export interface AxmlNode {
  nodeName: string;
  attributes: AxmlAttribute[];
  childNodes: AxmlNode[];
  namespaceURI?: string | null;
}

export class AxmlParser {
  private view: DataView;
  private strings: string[] = [];
  private cursor = 0;

  constructor(private data: Uint8Array) {
    this.view = new DataView(data.buffer, data.byteOffset, data.byteLength);
  }

  parse(): AxmlNode {
    this.strings = this.parseStringPool();
    // Skip any chunk until the XML document body
    const document = this.parseDocument();
    return document;
  }

  private parseStringPool(): string[] {
    const strings: string[] = [];
    // The file starts with an XML document header chunk (type 0x0003, 8 bytes)
    // followed by the string pool chunk (type 0x0001).
    this.cursor = 0;
    let firstChunkType = this.view.getUint16(0, true);
    let firstHeaderSize = this.view.getUint16(2, true);
    if (firstChunkType === CHUNK_XML) {
      // Skip the XML document header
      firstChunkType = this.view.getUint16(8, true);
      firstHeaderSize = this.view.getUint16(10, true);
      this.cursor = 8;
    }
    if (firstChunkType !== CHUNK_STRING_POOL) {
      throw new Error('Not an Android binary XML: missing string pool');
    }
    const stringCount = this.view.getUint32(this.cursor + 8, true);
    const flags = this.view.getUint32(this.cursor + 16, true);
    const stringsStart = this.view.getUint32(this.cursor + 20, true);
    const isUtf8 = (flags & STRING_FLAG_UTF8) !== 0;

    const offsets: number[] = [];
    const offsetBase = this.cursor + 28;
    for (let i = 0; i < stringCount; i++) {
      offsets.push(this.view.getUint32(offsetBase + i * 4, true));
    }

    for (let i = 0; i < stringCount; i++) {
      const off = this.cursor + stringsStart + offsets[i];
      strings.push(this.readPoolString(off, isUtf8));
    }
    void firstHeaderSize;
    return strings;
  }

  private readPoolString(offset: number, isUtf8: boolean): string {
    if (isUtf8) {
      let pos = offset;
      const len = this.readLength8(pos);
      pos += len.bytes;
      const byteLen = this.readLength8(pos);
      pos += byteLen.bytes;
      let end = pos + byteLen.length;
      if (end > this.data.length) end = this.data.length;
      const bytes = this.data.slice(pos, end);
      try {
        return new TextDecoder('utf-8').decode(bytes);
      } catch {
        return '';
      }
    } else {
      let pos = offset;
      const len = this.readLength16(pos);
      pos += len.bytes;
      let end = pos + len.length * 2;
      if (end > this.data.length) end = this.data.length;
      let result = '';
      for (let i = pos; i + 1 < end; i += 2) {
        const code = this.view.getUint16(i, true);
        result += String.fromCharCode(code);
      }
      return result;
    }
  }

  private readLength8(pos: number): { bytes: number; length: number } {
    let len = this.data[pos];
    if ((len & 0x80) === 0) return { bytes: 1, length: len };
    len = (len & 0x7f) << 8;
    len |= this.data[pos + 1];
    return { bytes: 2, length: len };
  }

  private readLength16(pos: number): { bytes: number; length: number } {
    let len = this.view.getUint16(pos, true);
    if ((len & 0x8000) === 0) return { bytes: 2, length: len };
    len = (len & 0x7fff) << 16;
    len |= this.view.getUint32(pos + 2, true);
    return { bytes: 6, length: len };
  }

  private parseDocument(): AxmlNode {
    // Walk chunks after the string pool. The XML document chunk (0x0003)
    // contains the string pool, optional resource map, then the element tree.
    let cursor = this.cursor;
    if (cursor === 0) {
      cursor = 8;
    }
    // Advance past the string pool chunk itself
    const poolSize = this.view.getUint32(cursor + 4, true);
    cursor += poolSize > 0 ? poolSize : 0;

    // Determine the end of the XML document chunk (bounded by the first chunk's size)
    let chunkEnd = this.data.length;
    const xmlSize = this.view.getUint32(4, true);
    if (xmlSize > 0 && xmlSize <= this.data.length) {
      chunkEnd = xmlSize;
    }

    // Skip the resource map chunk (0x0180) if present, then parse the element tree
    const resMapType = this.view.getUint16(cursor, true);
    if (resMapType === CHUNK_RESOURCE_MAP) {
      const resMapSize = this.view.getUint32(cursor + 4, true);
      cursor += resMapSize > 0 ? resMapSize : 0;
    }

    const doc = this.parseElementTree(cursor, chunkEnd);
    if (doc) return doc;
    throw new Error('Invalid binary XML: no document element');
  }

  private parseElementTree(start: number, end: number): AxmlNode | null {
    let cursor = start;
    let root: AxmlNode | null = null;
    let current: AxmlNode | null = null;
    const stack: AxmlNode[] = [];

    while (cursor + 8 <= end) {
      const chunkType = this.view.getUint16(cursor, true);
      const headerSize = this.view.getUint16(cursor + 2, true);
      const chunkSize = this.view.getUint32(cursor + 4, true);
      if (chunkSize === 0 || cursor + chunkSize > end) break;

      switch (chunkType) {
        case CHUNK_START_ELEMENT: {
          const el = this.parseStartElement(cursor + headerSize, cursor + chunkSize);
          if (!root) {
            root = el;
            current = el;
            stack.push(el);
          } else {
            current?.childNodes.push(el);
            stack.push(el);
            current = el;
          }
          break;
        }
        case CHUNK_END_ELEMENT: {
          stack.pop();
          current = stack.length > 0 ? stack[stack.length - 1] : null;
          break;
        }
        default:
          break;
      }
      cursor += chunkSize;
    }
    return root;
  }

  private parseStartElement(attrStart: number, attrEnd: number): AxmlNode {
    // attrStart points at the ResXMLTree_attrExt (after the 16-byte ResXMLTree_node:
    // header(8) + lineNumber(4) + comment(4)).
    // ResXMLTree_attrExt: ns(i32) name(i32) attributeStart(u16) attributeSize(u16)
    // attributeCount(u16) idIndex(u16) classIndex(u16) styleIndex(u16)
    const nsRef = this.view.getInt32(attrStart, true);
    const nameRef = this.view.getInt32(attrStart + 4, true);
    const attributeStart = this.view.getUint16(attrStart + 8, true);
    const attributeSize = this.view.getUint16(attrStart + 10, true);
    const attrCount = this.view.getUint16(attrStart + 12, true);

    const node: AxmlNode = {
      nodeName: this.strings[nameRef] || 'unknown',
      attributes: [],
      childNodes: [],
      namespaceURI: nsRef > 0 ? this.strings[nsRef] : null,
    };

    const attrSize = attributeSize > 0 ? attributeSize : 20;
    let pos = attrStart + (attributeStart > 0 ? attributeStart : 20);
    for (let i = 0; i < attrCount; i++) {
      if (pos + 20 > attrEnd) break;
      const aNsRef = this.view.getInt32(pos, true);
      const aNameRef = this.view.getInt32(pos + 4, true);
      const aValueRef = this.view.getInt32(pos + 8, true);
      const dataType = this.data[pos + 15];
      const data = this.view.getUint32(pos + 16, true);

      let value: string | number | boolean | null = null;
      let typeName = 'unknown';
      if (aValueRef > 0 && this.strings[aValueRef] !== undefined) {
        value = this.strings[aValueRef];
        typeName = 'string';
      }
      if (value === null) {
        const typed = this.resolveTypedValue(dataType, data);
        value = typed.value;
        typeName = typed.type;
      }

      const name = this.strings[aNameRef] || `attr${i}`;
      node.attributes.push({ name, value, typedValue: { type: typeName, value, data } });
      pos += attrSize;
    }

    return node;
  }

  private resolveTypedValue(dataType: number, data: number): { type: string; value: string | number | boolean | null } {
    switch (dataType) {
      case 0x01: // reference
        return { type: 'reference', value: data };
      case 0x03: // string (index)
        return { type: 'string', value: this.strings[data] ?? null };
      case 0x04: // float
        return { type: 'float', value: new Float32Array([data])[0] };
      case 0x10: // int dec
      case 0x11: // int hex
        return { type: 'int', value: data };
      case 0x12: // boolean
        return { type: 'boolean', value: data !== 0 };
      case 0x13: // flags
        return { type: 'flags', value: data };
      case 0x05: // dimension
        return { type: 'dimension', value: data };
      default:
        return { type: 'unknown', value: data };
    }
  }
}

export function parseAxml(data: Uint8Array): AxmlNode {
  return new AxmlParser(data).parse();
}

// Collapse an AXML element into attribute map, keeping android namespace attrs clean
export function collapseAttributes(el: AxmlNode): Record<string, any> {
  const out: Record<string, any> = {};
  for (const attr of el.attributes) {
    out[attr.name] = attr.value;
  }
  return out;
}
