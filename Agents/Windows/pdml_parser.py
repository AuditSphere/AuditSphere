from typing import Dict, List, Optional, Any, Union
import xml.etree.ElementTree as ET

class Field:
    def __init__(self, attributes: Dict[str, str]):
        self._attributes = attributes
        self._children: List[Field] = []

    def add_child(self, field: 'Field') -> None:
        """Add a child field to this field."""
        self._children.append(field)

    def get_child(self, name: str) -> 'Field':
        """Get a child field by name."""
        for child in self._children:
            if child.get_name() == name:
                return child
        return NullField()

    def get_children(self) -> List['Field']:
        """Get all child fields."""
        return self._children

    def get_name(self) -> str:
        """Get field name."""
        return self._attributes.get('name', '')

    def get_value(self) -> str:
        """Get field value."""
        return self._attributes.get('show', '')

    def get_attribute(self, name: str, default: Any = None) -> Any:
        """Get field attribute."""
        return self._attributes.get(name, default)

    def __str__(self) -> str:
        return self.get_value()

    def __repr__(self) -> str:
        return f"Field(name='{self.get_name()}', value='{self.get_value()}')"

class NullField(Field):
    """A null object implementation of Field that returns defaults for all operations."""
    def __init__(self):
        super().__init__({})
        
    def add_child(self, field: 'Field') -> None:
        pass
        
    def get_child(self, name: str) -> 'NullField':
        return self
        
    def get_children(self) -> List['Field']:
        return []
        
    def get_name(self) -> str:
        return ''
        
    def get_value(self) -> str:
        return ''
        
    def get_attribute(self, name: str, default: Any = None) -> Any:
        return default

class Protocol:
    def __init__(self, attributes: Dict[str, str]):
        self._attributes = attributes
        self._root_fields: List[Field] = []
        
    def __getattr__(self, name: str) -> Field:
        """Get a field by name, called when normal attribute lookup fails."""
        field = self.get_field(name)
        if isinstance(field, NullField):
            raise AttributeError(f"Protocol '{self.get_name()}' has no field '{name}'")
        return field
    
    def add_field(self, field: Field, parent_field: Optional[Field] = None) -> None:
        """Add a field to the protocol."""
        if parent_field is None:
            self._root_fields.append(field)
        else:
            parent_field.add_child(field)

    def get_all_fields(self) -> List[Field]:
        """Get all fields recursively, including nested fields."""
        def collect_fields(fields: List[Field], accumulated_fields: List[Field]) -> None:
            for field in fields:
                accumulated_fields.append(field)
                collect_fields(field.get_children(), accumulated_fields)

        result: List[Field] = []
        collect_fields(self._root_fields, result)
        return result

    def get_field(self, name: str, index: Optional[int] = None) -> Field:
        """
        Get a field by name, searching recursively through all fields.
        Args:
            name: The name of the field to get
            index: The index of the field if multiple fields exist with the same name.
                  If None (default), returns the first field.
        """
        matching_fields = [field for field in self.get_all_fields() if field.get_name() == name]
        if matching_fields:
            try:
                if index is None:
                    index = 0
                return matching_fields[index]
            except IndexError:
                return NullField()
        return NullField()

    def get_field_count(self, name: str) -> int:
        """Get the number of fields with the given name."""
        return len([field for field in self.get_all_fields() if field.get_name() == name])

    def get_fields(self) -> List[Field]:
        """Get all root fields."""
        return self._root_fields

    def get_name(self) -> str:
        return self._attributes.get('name', '')

    def __str__(self) -> str:
        return self.get_name()

    def __repr__(self) -> str:
        return f"{self.get_name()}"
    
    def __getitem__(self, index: int) -> 'Protocol':
        """Support indexed access for backward compatibility."""
        if index == 0:
            return self
        raise IndexError(f"Protocol index {index} out of range")

class Packet:
    """Container for protocols and top-level fields."""
    def __init__(self):
        self.protocols: Dict[str, List[Protocol]] = {}
        self.fields: Dict[str, List[Field]] = {}
        
    def add_protocol(self, protocol: Protocol) -> None:
        """Add a protocol to the packet."""
        proto_name = protocol.get_name()
        if proto_name not in self.protocols:
            self.protocols[proto_name] = []
        self.protocols[proto_name].append(protocol)
        
    def add_field(self, field: Field) -> None:
        """Add a top-level field to the packet."""
        field_name = field.get_name()
        if field_name not in self.fields:
            self.fields[field_name] = []
        self.fields[field_name].append(field)
        
    def get_field(self, name: str, index: Optional[int] = None) -> Field:
        """
        Get a field by name from top-level fields.
        Args:
            name: The name of the field to get
            index: The index of the field if multiple fields exist with the same name.
                  If None (default), returns the first field.
        """
        if name in self.fields:
            try:
                if index is None:
                    index = 0
                return self.fields[name][index]
            except IndexError:
                return NullField()
        return NullField()
        
    def get_field_count(self, name: str) -> int:
        """Get the number of fields with the given name."""
        return len(self.fields.get(name, []))
        
    def get_all_fields(self) -> List[Field]:
        """Get all fields, including those in protocols."""
        result = []
        for fields in self.fields.values():
            result.extend(fields)
        for protocols in self.protocols.values():
            for protocol in protocols:
                result.extend(protocol.get_all_fields())
        return result

class ProtocolDict(dict):
    """Dictionary-like container for protocols with attribute access."""
    def __init__(self, packet: Packet):
        super().__init__(packet.protocols)
        self.packet = packet

    def __getattr__(self, name: str) -> Protocol:
        """Get the first protocol of the specified type."""
        try:
            protocols = super().__getitem__(name)
            if isinstance(protocols, list) and protocols:
                return protocols[0]
            return protocols
        except KeyError:
            raise AttributeError(f"Protocol '{name}' not found")

    def __getitem__(self, key: str) -> Union[Protocol, List[Protocol]]:
        """Get protocol(s) by name."""
        return super().__getitem__(key)

    def get_field(self, name: str, index: Optional[int] = None) -> Field:
        """
        Get a top-level field by name and index.
        Args:
            name: The name of the field to get
            index: The index of the field if multiple fields exist with the same name.
                  If None (default), returns the first field.
        """
        return self.packet.get_field(name, index)
        
    def get_field_count(self, name: str) -> int:
        """Get the number of fields with the given name."""
        return self.packet.get_field_count(name)

class PDMLParser:
    @staticmethod
    def parse_string(xml_string: str) -> ProtocolDict:
        """Parse PDML from a string."""
        root = ET.fromstring(xml_string)
        packet = PDMLParser._parse_packet(root)
        return ProtocolDict(packet)

    @staticmethod
    def _parse_packet(packet_element: ET.Element) -> Packet:
        """Parse packet element, its protocols and top-level fields."""
        if packet_element.tag != 'packet':
            raise ValueError("Root element must be 'packet'")

        packet = Packet()
        
        for proto_elem in packet_element.findall('proto'):
            protocol = PDMLParser._parse_protocol(proto_elem)
            packet.add_protocol(protocol)
            
        for field_elem in packet_element.findall('field'):
            field = PDMLParser._parse_field(field_elem)
            packet.add_field(field)

        return packet

    @staticmethod
    def _parse_protocol(proto_element: ET.Element) -> Protocol:
        """Parse protocol element and its fields."""
        attributes = {
            'name': proto_element.get('name', ''),
            'showname': proto_element.get('showname', ''),
            'size': proto_element.get('size', '0'),
            'pos': proto_element.get('pos', '0')
        }

        protocol = Protocol(attributes)
        
        for field_elem in proto_element.findall('./field'):
            field = PDMLParser._parse_field(field_elem)
            protocol.add_field(field)

        return protocol
        
    @staticmethod
    def _parse_field(field_elem: ET.Element, parent_field: Optional[Field] = None) -> Field:
        """Parse field element and its children."""
        field_attrs = {
            'name': field_elem.get('name', ''),
            'show': field_elem.get('show', ''),
            'showname': field_elem.get('showname', ''),
            'pos': field_elem.get('pos', '0'),
            'size': field_elem.get('size', '0'),
            'value': field_elem.get('value', ''),
            'unmaskedvalue': field_elem.get('unmaskedvalue', '')
        }
        
        field = Field(field_attrs)
        
        for child_elem in field_elem.findall('./field'):
            child_field = PDMLParser._parse_field(child_elem, field)
            field.add_child(child_field)
            
        return field
