# SNMP Tools Documentation

This documentation provides a comprehensive guide to using the SNMP Tools, including the SNMP OID Fetcher, SNMP Set, SNMP OID Table Fetcher, SNMP OID Subtree Fetcher, and SNMP Walker Tools. These tools are designed to facilitate the management of SNMP-enabled devices by fetching and setting SNMP Object Identifiers (OIDs) and exploring SNMP OID trees.

### Description

The SNMP OID Fetcher Tool is tailored for retrieving SNMP Object Identifiers (OIDs) or lists of OIDs based on detailed input parameters.

## Installation

To use these SNMP tools in your Node-RED environment, follow these steps:

1. Clone or download this repository to your local machine.
2. Open Node-RED.
3. Navigate to the "Manage Palette" option in the menu.
4. Click on the "Install" tab.
5. Choose "Install from file" and select the downloaded repository file.
6. Once installed, the SNMP nodes will be available in the Node-RED palette.

### How It Works

Activated by any input, the tool processes the provided parameters to fetch the specified OIDs.

### Input Parameters

- `msg.host` - The network host address.
- `msg.port` - The network port.
- `msg.community` - The SNMP community string.
- `msg.username` - (For SNMP V3 only) The username for authentication.
- `msg.auth` - (For SNMP V3 only) Specifies the security level for SNMP V3 communication. Options include 'noAuthNoPriv', 'authNoPriv', and 'authPriv'.
- `msg.authProtocol` - (For SNMP V3 only) Defines the authentication protocol.
- `msg.authKey` - (For SNMP V3 only) The key for digest-based message integrity.
- `msg.privProtocol` - (For SNMP V3 only) Specifies the encryption protocol.
- `msg.privKey` - (For SNMP V3 only) The key for message encryption.
- `msg.oid(s)` - Specifies the OID(s) to be fetched.

### OID Format

OIDs must be numeric. The prefix "iso." is equivalent to "1".

### Output

The tool provides output in `msg.payload`, containing the data of the fetched OIDs.

## SNMP Set Tool

### Description

This document provides details on the SNMP Set Tool, designed for setting specific values on network devices via SNMP.

Types can be:

 * `Boolean`
 * `Integer`
 * `OctetString`
 * `Null`
 * `OID`
 * `IpAddress`
 * `Counter`
 * `Gauge`
 * `TimeTicks`
 * `Opaque`
 * `Integer32`
 * `Counter32`
 * `Gauge32`
 * `Unsigned32`
 * `Counter64`
 * `NoSuchObject`
 * `NoSuchInstance`
 * `EndOfMibView`

### Usage

To incorporate these nodes into your Node-RED workflows, start by selecting and dragging them from the Node-RED palette to your workspace. Then, adjust the input parameters to meet your specific needs. By establishing connections between these nodes, you can seamlessly execute SNMP operations.

### Input Parameters

(Similar to the SNMP OID Fetcher Tool, with the addition of `msg.varbinds` for specifying variables to set.)

### Data Types and Formats

Numeric inputs must be actual numbers, not strings. OIDs must be numeric, with "iso." being equivalent to "1".

## SNMP OID Table Fetcher Tool

### Description

This guide details the SNMP OID Table Fetcher Tool, which retrieves complete tables of SNMP OIDs based on specified inputs.

### Activation

Activated by any input, offering a responsive activation mechanism.

### Input Parameters

(Similar to the SNMP OID Fetcher Tool, with `msg.oids` indicating the OID of the table to be fetched.)

### Output

After a successful fetch, the tool outputs the data of the fetched OID table in `msg.payload`.

## SNMP OID Subtree Fetcher Tool

### Description

Introduces the SNMP OID Subtree Fetcher Tool, crafted to query all OIDs starting from a specified base OID.

### Activation and Operation

Activated by any input, begins fetching operations for the specified OID subtree upon receiving a trigger.

### Input Parameters

(Similar to the SNMP OID Fetcher Tool, with `msg.oids` as the base OID for subtree fetching.)

### Output

Provides the fetched OID subtree data in `msg.payload`.

## SNMP Walker Tool

### Description

The SNMP Walker Tool is crafted to fetch all nodes from a specified start OID to the end of an SNMP table.

### Activation and Functionality

Commences a "walk" from the specified starting OID upon any input.

### Input Parameters

(Similar to the SNMP OID Fetcher Tool, with `msg.oids` as the starting OID for the walk.)

### OID Format and Behavior

The OID must be numeric. The tool's "walking" behavior provides a unique approach to OID tree traversal.

### Output

Provides the data fetched from the OID tree in `msg.payload`.

### Example of usage

```json
{
  "host": "192.168.1.1",
  "community": "public",
  "oids": "1.3.6.1.2.1.1"
}
```

## License

This project is licensed under the [MIT License](LICENSE).