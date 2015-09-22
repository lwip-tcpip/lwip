/*! \mainpage lwIP Documentation
 *
 * \section intro_sec Introduction
 *
 * lwIP is a small independent implementation of the TCP/IP protocol suite that has been developed by Adam Dunkels at the Computer and Networks Architectures (CNA) lab at the Swedish Institute of Computer Science (SICS).
 *
 * The focus of the lwIP TCP/IP implementation is to reduce resource usage while still having a full scale TCP. This making lwIP suitable for use in embedded systems with tens of kilobytes of free RAM and room for around 40 kilobytes of code ROM.
 *
 * \section lwip_features_sec lwIP features:
 *
 * \li \c IP (Internet Protocol) including packet forwarding over multiple network interfaces\n
 * \li \c ICMP (Internet Control Message Protocol) for network maintenance and debugging\n
 * \li \c IGMP (Internet Group Management Protocol) for multicast traffic management\n
 * \li \c UDP (User Datagram Protocol) including experimental UDP-lite extensions\n
 * \li \c TCP (Transmission Control Protocol) with congestion control, RTT estimation and fast recovery/fast retransmit\n
 * \li \c raw/native API for enhanced performance\n
 * \li \c Optional Berkeley-like socket API\n
 * \li \c DNS (Domain names resolver)\n
 * \li \c SNMP (Simple Network Management Protocol)\n
 * \li \c DHCP (Dynamic Host Configuration Protocol)\n
 * \li \c AUTOIP (for IPv4, conform with RFC 3927)\n
 * \li \c PPP (Point-to-Point Protocol)\n
 * \li \c ARP (Address Resolution Protocol) for Ethernet\n
 *
 * \section install_sec Documentation
 *
 * Development of lwIP is hosted on Savannah, a central point for software development, maintenance and distribution. Everyone can help improve lwIP by use of Savannah's interface, Git and the mailing list. A core team of developers will commit changes to the Git source tree.\n
 *   http://savannah.nongnu.org/projects/lwip/\n
 * \n
 * The original out-dated homepage of lwIP and Adam Dunkels' papers on lwIP are at the official lwIP home page:\n
 *   http://www.sics.se/~adam/lwip/\n
 * \n
 * Self documentation of the source code is regularly extracted from the current Git sources and is available from this web page:\n
 *   http://www.nongnu.org/lwip/\n
 * \n
 * There is now a constantly growin wiki about lwIP at\n
 *   http://lwip.wikia.com/\n
 * \n
 * Also, there are mailing lists you can subscribe at\n
 *   http://savannah.nongnu.org/mail/?group=lwip\n
 * plus searchable archives:\n
 *   http://lists.nongnu.org/archive/html/lwip-users/\n
 *   http://lists.nongnu.org/archive/html/lwip-devel/\n
 * \n
 * Reading Adam's papers, the files in docs/, browsing the source code documentation and browsing the mailing list archives is a good way to become familiar with the design of lwIP.\n
 *
 */
