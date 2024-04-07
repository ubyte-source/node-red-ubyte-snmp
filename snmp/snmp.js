
module.exports = function (RED) {

  "use strict";

  // A global object to hold active SNMP sessions, keyed by session ID.
  const sessions = {};
  // Import the net-snmp library to work with SNMP (Simple Network Management Protocol).
  const SNMP = require("net-snmp");
  // Import the uuid library to generate unique identifiers.
  const { v4: uuidv4 } = require("uuid");
  // Import ip-address library for working with IPv4 and IPv6 addresses.
  const { Address4, Address6 } = require('ip-address');

  /**
   * Generates a unique UUID (Universally Unique Identifier).
   *
   * This function utilizes the uuidv4 library to generate and return
   * a version 4 UUID, which is randomly generated and has a high probability
   * of uniqueness. Version 4 UUIDs are universally unique identifiers that
   * are generated using random or pseudo-random numbers.
   *
   * @return {string} A string representation of a version 4 UUID.
   */
  function generateUUID() {
    // Return a new UUID.
    return uuidv4();
  }

  /**
   * Opens a new SNMP session based on the specified parameters and SNMP version. It supports creating
   * sessions for both SNMPv3 and earlier versions by adjusting the session creation logic based on the
   * provided options. The created session is stored in a global sessions object for later management.
   *
   * @param {string} sessionid - A unique identifier for the session to facilitate tracking and management.
   * @param {string} host - The target host address for the SNMP session.
   * @param {Object} user - Contains user details. For SNMPv3, it includes security options. For v1/v2c, it includes the community string.
   * @param {Object} options - Configuration options for the session, including the SNMP version and other parameters.
   * @returns The SNMP session object, allowing for further operations like GET, SET, etc.
   */
  function openSession(sessionid, host, user, options) {
    try {
      // Determine the SNMP version and create the session accordingly.
      if (SNMP.Version3 === options.version) {
        // For SNMPv3, use detailed user and security options.
        sessions[sessionid] = SNMP.createV3Session(host, user, options);
      } else {
        // For SNMPv1 and v2c, a community string is expected within the user object.
        if (false === user.hasOwnProperty('community'))
          throw new Error("SNMP v1/v2c requires a community string in the user parameter.");
        sessions[sessionid] = SNMP.createSession(host, user.community, options);
      }
      return sessions[sessionid];
    } catch (error) {
      return null;
    }
  }

  /**
   * Closes an SNMP session identified by its session ID. This function ensures that
   * resources are properly released and the session is cleanly terminated. It safely
   * handles any errors that may occur during session closure to avoid crashes or leaks.
   *
   * @param {string} sessionid - The unique identifier for the SNMP session to be closed.
   */
  function closeSession(sessionid) {
    // Early exit if no session exists with the provided ID to avoid unnecessary processing.
    if (!sessions.hasOwnProperty(sessionid)) return;
    try {
      // Safely attempt to clean up the session.
      // First, remove all event listeners to prevent potential memory leaks.
      sessions[sessionid].removeAllListeners();
      // Then, attempt to close the session to gracefully terminate the connection.
      sessions[sessionid].close();
    } catch (e) {
      // Log the error to aid in debugging, but allow the function to continue execution
      // to ensure the session is removed from the sessions object.
    }
    // Regardless of the try-catch outcome, delete the session from the global sessions object
    // to clean up and ensure it's no longer referenced or accessible.
    delete sessions[sessionid];
  }

  /**
   * Prepares and returns SNMP session options, tailored to specific SNMP versions and security requirements.
   *
   * @param {Object} node - The Node-RED node containing default configuration.
   * @param {Object} msg - The message object that may override node settings.
   * @returns {Object} An object containing SNMP session settings including host, session ID, user, and other options.
   */
  function prepareSnmpOptions(node, msg) {
    // Basic session setup with defaults and overrides from msg.
    let sessionOptions = {
      host: msg.host || node.host,
      sessionid: generateUUID(),
      user: {},
      options: {
        version: getSnmpVersion(msg.version || node.version),
        port: msg.port || node.port || 161,
        timeout: msg.timeout || node.timeout || 4000,
        retries: msg.retries || node.retries || 1
      }
    };
    // Checking if certain properties exist in the msg object and assigns it to corresponding properties
    if (msg.engineID) sessionOptions.options.engineID = msg.engineID;
    if (msg.backoff) sessionOptions.options.backoff = msg.backoff;
    if (msg.backwardsGetNexts) sessionOptions.options.backwardsGetNexts = msg.backwardsGetNexts;
    if (msg.idBitsSize) sessionOptions.options.idBitsSize = msg.idBitsSize;
    // Enhance session options based on the SNMP version.
    switch (sessionOptions.options.version) {
      case SNMP.Version1:
      case SNMP.Version2c:
        sessionOptions.user.community = msg.community || node.community;
        break;
      case SNMP.Version3:
        configureV3Security(sessionOptions, msg, node);
        break;
      default:
        // Default to Version2c if unspecified.
        node.warn("Unsupported SNMP version specified. Using SNMP Version2c as default.");
        sessionOptions.options.version = SNMP.Version2c;
    }
    // Determine and set the IP transport version.
    const ipv = parseIP(sessionOptions.host);
    sessionOptions.host = ipv.ip;
    sessionOptions.options.transport = ipv.version === 6
      ? 'udp6'
      : 'udp4';
    return sessionOptions;
  }

  /**
   * Translates version string to SNMP version constant.
   *
   * @param {string} versionString - The version string (v1, v2c, or v3).
   * @returns SNMP version constant.
   */
  function getSnmpVersion(versionString) {
    const versionMap = {
      "v1": SNMP.Version1,
      "v3": SNMP.Version3,
      "v2c": SNMP.Version2c
    };
    return versionMap[versionString] || SNMP.Version2c;
  }

  /**
   * Configures SNMP v3 security settings.
   *
   * @param {Object} options - The session options object to be enhanced.
   * @param {Object} msg - The incoming message object.
   * @param {Object} node - The node configuration object.
   */
  function configureV3Security(options, msg, node) {
    const auth = msg.auth || node.auth;
    options.user = {
      name: msg.username || node.username || "",
      level: determineSecurityLevel(auth),
      authProtocol: getAuthProtocol(msg.authProtocol || node.authProtocol),
      authKey: msg.authKey || node.authKey || "",
      privKey: msg.privKey || node.privKey || "",
      privProtocol: auth === "authPriv"
        ? getPrivProtocol(msg.privProtocol || node.privProtocol)
        : SNMP.PrivProtocols.none
    };
  }

  /**
   * Determines the SNMP security level based on authentication and privacy settings.
   *
   * @param {string} auth - The authentication setting.
   * @returns SNMP security level constant.
   */
  function determineSecurityLevel(auth) {
    if (auth === "authPriv") return SNMP.SecurityLevel.authPriv;
    if (auth === "authNoPriv") return SNMP.SecurityLevel.authNoPriv;
    return SNMP.SecurityLevel.noAuthNoPriv;
  }

  /**
   * Returns the appropriate authentication protocol constant.
   *
   * @param {string} authProtocol - The authentication protocol setting.
   * @returns SNMP authentication protocol constant.
   */
  function getAuthProtocol(authProtocol) {
    return authProtocol === "SHA"
      ? SNMP.AuthProtocols.sha
      : SNMP.AuthProtocols.md5;
  }

  /**
   * Returns the appropriate privacy protocol constant.
   *
   * @param {string} privProtocol - The privacy protocol setting.
   * @returns SNMP privacy protocol constant.
   */
  function getPrivProtocol(privProtocol) {
    return privProtocol === "AES"
      ? SNMP.PrivProtocols.aes
      : SNMP.PrivProtocols.des;
  }

  /**
   * Parses an IP address string to extract information such as its version, original string, and hexadecimal representation.
   * Supports both IPv4 and IPv6 address formats.
   *
   * @param {string} ip - The IP address string to parse.
   * @returns {Object} An object containing details about the parsed IP address.
   */
  function parseIP(ip) {
    // Initialize the response object with default values.
    let response = {
      ip: '',         // The original IP address string.
      hex: '',        // The hexadecimal representation of the IP address.
      version: null   // The IP version (4 or 6).
    };
    try {
      // Attempt to parse the IP address as IPv4.
      const addr4 = new Address4(ip);
      // If successful, populate the response object with IPv4 details.
      response.ip = addr4.address;    // Original IPv4 address string.
      response.hex = addr4.toHex();   // Hexadecimal representation of the IPv4 address.
      response.version = 4;           // Indicate IPv4 version.
    } catch (error) {
      try {
        // If parsing as IPv4 fails, attempt to parse as IPv6.
        const addr6 = new Address6(ip);
        // If successful, populate the response object with IPv6 details.
        response.ip = addr6.address;    // Original IPv6 address string.
        response.hex = addr6.toHex();   // Hexadecimal representation of the IPv6 address.
        response.version = 6;           // Indicate IPv6 version.
      } catch (error) {
        // If parsing as IPv6 also fails, no further action is taken, and default response values are retained.
        // The response object remains unchanged with default values.
      }
    }
    // Return the response object containing IP address details.
    return response;
  }

  /**
   * This function cleans OIDs by removing all whitespace characters.
   * 
   * @param {string} oids - The OIDs string to be cleaned.
   * @returns {string} The cleaned OIDs string.
   */
  function OIDClean(oids) {
    // Uses a regular expression to replace all occurrences of whitespace
    return oids.replace(/\s/g, "");
  }

  /**
   * Constructs a new SNMPNode instance.
   * @param {Object} config - Configuration object for the SNMPNode.
   */
  function SNMPNode(config) {
    const node = this;
    RED.nodes.createNode(node, config);
    node.oids = config.oids || "";
    node.on("input", function (msg, send, done) {
      // Prepare SNMP session options based on the incoming message and node configuration.
      const { host, sessionid, user, options } = prepareSnmpOptions(node, msg);
      // Determine the OIDs to query, preferring the message payload over node configuration.
      const oids = msg.oids || node.oids;
      // Proceed only if there are OIDs specified.
      if (oids) {
        // Open an SNMP session using the prepared options.
        let session = openSession(sessionid, host, user, options);
        if (session === null) {
          // Log the error to the Node-RED debug pane.
          node.error("A session could not be established");
          return;
        }
        // Handle session errors gracefully.
        session.on("error", function (e) {
          // Log any errors that occur during the session.
          node.error(e);
        });
        // Perform the SNMP 'get' operation using the specified OIDs.
        const oidssplit = OIDClean(oids).split(String.fromCharCode(44));
        session.get(oidssplit, function (error, varbinds) {
          if (error) {
            // Handle SNMP errors by logging them.
            node.error(error.toString());
          } else {
            // Process each variable binding received in response.
            for (let i = 0; i < varbinds.length; i++) {
              let varbind = varbinds[i];
              if (SNMP.isVarbindError(varbind)) {
                // Check for and handle errors specific to the variable binding.
                node.error(SNMP.varbindError(varbind));
              }
              // Annotate the variable binding with a human-readable type string.
              varbind.tstr = SNMP.ObjectType[varbind.type];
            }
            // Send the collected response data as the payload in the output message.
            msg.oids = oids;
            msg.payload = varbinds;
            send(msg);
          }
          // Close the SNMP session now that we're done with it.
          closeSession(sessionid);
          if (done) done();
        });
      } else {
        // Warn if no OIDs were specified for querying.
        node.warn("No OID(s) to search for");
      }
    });
  }

  // Register the new node type in the Node-RED runtime.
  RED.nodes.registerType("SNMP", SNMPNode);

  /**
   * Constructor function for SNMP Set Node.
   * @param {Object} config - Configuration object for the SNMP Set Node.
   */
  function SNMPNodeSet(config) {
    const node = this;
    RED.nodes.createNode(node, config);
    node.varbinds = config.varbinds;
    // If varbinds is an empty string, it is considered not provided and
    // thus deleted from the node configuration.
    if (typeof node.varbinds !== 'string'
      || 0 === node.varbinds.trim().length) delete node.varbinds;
    node.on("input", function (msg, send, done) {
      // Prepare SNMP session options based on the incoming message and the node configuration.
      const { host, sessionid, user, options } = prepareSnmpOptions(node, msg);
      // Determine the varbinds to use for the SNMP Set operation, preferring the node configuration over the message payload.
      const varbinds = node.varbinds
        ? JSON.parse(node.varbinds)
        : msg.varbinds;
      // Proceed only if varbinds are specified.
      if (varbinds) {
        // Ensure each varbind has the correct data type for the SNMP operation.
        for (let i = 0; i < varbinds.length; i++)
          varbinds[i].type = SNMP.ObjectType[varbinds[i].type];
        // Open an SNMP session using the prepared options.
        let session = openSession(sessionid, host, user, options);
        if (session === null) {
          // Log the error to the Node-RED debug pane.
          node.error("A session could not be established");
          return;
        }
        // Handle session errors.
        session.on("error", function (e) {
          // Log any errors that occur during the session.
          node.error(e);
        });
        // Execute the SNMP Set operation with the specified varbinds.
        session.set(varbinds, function (error, varbinds) {
          if (error) {
            // If there's an error in setting, log it.
            node.error(error.toString());
          } else {
            // Check the response varbinds for errors.
            for (let i = 0; i < varbinds.length; i++) {
              if (!SNMP.isVarbindError(varbinds[i])) continue;
              node.error(SNMP.varbindError(varbinds[i]));
            }
          }
          // Close the session after the operation is complete.
          closeSession(sessionid);
          if (done) done();
        });
      } else {
        // Warn if there are no varbinds specified for the SNMP Set operation.
        node.warn("No varbinds to set");
      }
    });
  }

  // Register the SNMP Set Node with Node-RED.
  RED.nodes.registerType("SNMP Set", SNMPNodeSet);

  /**
   * Constructor function for SNMP Table Node in Node-RED.
   * @param {Object} config - Configuration object for the SNMP Table Node.
   */
  function SNMPNodeTable(config) {
    const node = this;
    RED.nodes.createNode(node, config);
    node.oid = config.oid || "";
    node.on("input", function (msg, send, done) {
      // Prepare SNMP session options based on incoming message and node configuration.
      const { host, sessionid, user, options } = prepareSnmpOptions(node, msg);
      // Determine the OID to use, preferring message payload over node configuration.
      const oid = msg.oid || node.oid;
      // Proceed only if OID are provided.
      if (oid) {
        // Set a fixed number for maxRepetitions in the SNMP Table operation, used for bulk retrieval.
        const maxRepetitions = 20;
        // Open an SNMP session with the prepared options.
        let session = openSession(sessionid, host, user, options);
        if (session === null) {
          // Log the error to the Node-RED debug pane.
          node.error("A session could not be established");
          return;
        }
        // Handle session errors.
        session.on("error", function (e) {
          // Log any errors that occur during the session.
          node.error(e);
        });
        // Execute the SNMP Table operation.
        const oidclean = OIDClean(oid);
        session.table(oidclean, maxRepetitions, function (error, table) {
          if (error) {
            // Log and handle any errors that occur during table retrieval.
            node.error(error.toString());
          } else {
            // Send the table as payload in the output message.
            msg.payload = table;
            send(msg);
          }
          // Close the SNMP session now that operations are complete.
          closeSession(sessionid);
          if (done) done();
        });
      } else {
        // Warn if no OID were provided for the SNMP Table operation.
        node.warn("No OID to search for");
      }
    });
  }

  // Register the SNMP Table Node with Node-RED.
  RED.nodes.registerType("SNMP Table", SNMPNodeTable);

  /**
   * Constructor function for SNMP Subtree Node in Node-RED.
   * @param {Object} config - Configuration object for the SNMP Subtree Node.
   */
  function SNMPNodeSubtree(config) {
    let node = this;
    RED.nodes.createNode(node, config);
    node.oid = config.oid || "";
    node.on("input", function (msg, send, done) {
      // Prepare SNMP session options based on incoming message and node configuration.
      const { host, sessionid, user, options } = prepareSnmpOptions(node, msg);
      // Determine the OID to use, preferring the message payload over node configuration.
      const oid = msg.oid || node.oid;
      // Proceed only if OID are provided.
      if (oid) {
        // Prepare an array to collect the response and set a fixed number for maxRepetitions for bulk retrieval.
        const response = [];
        const maxRepetitions = 20;
        // Define a callback function to process each chunk of data as it is received.
        const feedCb = function (varbinds) {
          for (let i = 0; i < varbinds.length; i++) {
            if (SNMP.isVarbindError(varbinds[i])) {
              // Handle any errors encountered for individual varbinds.
              node.error(SNMP.varbindError(varbinds[i]));
              continue;
            }
            // Accumulate successful varbind results in the response array.
            response.push({
              oid: varbinds[i].oid,
              value: varbinds[i].value
            });
          }
        };
        // Open an SNMP session with the prepared options.
        let session = openSession(sessionid, host, user, options);
        if (session === null) {
          // Log the error to the Node-RED debug pane.
          node.error("A session could not be established");
          return;
        }
        // Handle session errors.
        session.on("error", function (e) {
          // Log any errors that occur during the session.
          node.error(e);
        });
        // Execute the SNMP Subtree operation.
        const oidclean = OIDClean(oid);
        session.subtree(oidclean, maxRepetitions, feedCb, function (error) {
          if (error) {
            // Log and handle any errors that occur during the subtree retrieval.
            node.error(error.toString());
          } else {
            // Send the collected response data as the payload in the output message.
            msg.payload = response;
            send(msg);
          }
          // Close the SNMP session now that operations are complete.
          closeSession(sessionid);
          if (done) done();
        });
      } else {
        // Warn if no OID were provided for the SNMP Subtree operation.
        node.warn("No OID to search");
      }
    });
  }

  // Register the SNMP Subtree Node with Node-RED.
  RED.nodes.registerType("SNMP Subtree", SNMPNodeSubtree);

  /**
  * Constructor function for SNMP Walker Node in Node-RED.
  * @param {Object} config - Configuration object for the SNMP Walker Node.
  */
  function SNMPNodeWalk(config) {
    const node = this;
    RED.nodes.createNode(node, config);
    node.oid = config.oid || "";
    node.on("input", function (msg, send, done) {
      // Prepare SNMP session options based on incoming message and node configuration.
      const { host, sessionid, user, options } = prepareSnmpOptions(node, msg);
      // Determine the OID to use, preferring message payload over node configuration.
      const oid = msg.oid || node.oid;
      // Proceed only if OID are provided.
      if (oid) {
        // Prepare an array to collect the response and set a fixed number for maxRepetitions for bulk retrieval.
        const response = [];
        const maxRepetitions = 20;
        // Define a callback function to process each varbind as it is received.
        const feedCb = function (varbinds) {
          for (let i = 0; i < varbinds.length; i++) {
            if (SNMP.isVarbindError(varbinds[i])) {
              // Handle any errors encountered for individual varbinds.
              node.error(SNMP.varbindError(varbinds[i]));
              continue;
            }
            // Accumulate successful varbind results in the response array.
            response.push({
              oid: varbinds[i].oid,
              value: varbinds[i].value
            });
          }
        };
        // Open an SNMP session with the prepared options.
        let session = openSession(sessionid, host, user, options);
        if (session === null) {
          // Log the error to the Node-RED debug pane.
          node.error("A session could not be established");
          return;
        }
        // Handle session errors.
        session.on("error", function (e) {
          // Log any errors that occur during the session.
          node.error(e);
        });
        // Execute the SNMP Walk operation.
        const oidclean = OIDClean(oid);
        session.walk(oidclean, maxRepetitions, feedCb, function (error) {
          if (error) {
            // Log and handle any errors that occur during the walk.
            node.error(error.toString());
          } else {
            // Send the collected response data as the payload in the output message.
            msg.payload = response;
            send(msg);
          }
          // Close the SNMP session now that operations are complete.
          closeSession(sessionid);
          if (done) done();
        });
      } else {
        // Warn if no OID were provided for the SNMP Walk operation.
        node.warn("No OID to search for");
      }
    });
  }

  // Register the SNMP Walker Node with Node-RED.
  RED.nodes.registerType("SNMP Walker", SNMPNodeWalk);
};
