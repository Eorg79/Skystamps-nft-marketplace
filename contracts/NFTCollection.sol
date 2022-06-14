// SPDX-License-Identifier: MIT
pragma solidity 0.8.14;

import "@openzeppelin/contracts/access/AccessControl.sol";
import "@openzeppelin/contracts/token/ERC721/ERC721.sol";
import "@openzeppelin/contracts/token/ERC721/extensions/ERC721URIStorage.sol";
import "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import "@openzeppelin/contracts/utils/cryptography/draft-EIP712.sol";
import "@openzeppelin/contracts/proxy/utils/Initializable.sol";

contract NFTCollection is ERC721URIStorage, Initializable, EIP712, AccessControl {
    using ECDSA for bytes32;
    
    string public collectionName;
    string public collectionSymbol;
    bytes32 public constant MINTER_ROLE = keccak256("MINTER_ROLE");
    mapping (address => uint256) balance;

    struct TokenVoucher {
        address collectionAddress;
        uint tokenId;
        uint price;
        string tokenURI;
        bytes signature;
    }

    event TokenMinted(
        uint tokenId,
        address recipient,
        string tokenURI
    );

    constructor () ERC721("name", "symbol") EIP712("Voucher", "1") {}

    function initialize(string memory _name, string memory _symbol, address payable minter) public initializer {
        collectionName = _name;
        collectionSymbol = _symbol;
         _setupRole(MINTER_ROLE, minter);
    }

    function _hash(TokenVoucher memory _tokenVoucher) internal view returns (bytes32) {
    return _hashTypedDataV4(keccak256(abi.encode(
      keccak256("TokenVoucher(address collectionAddress,uint256 tokenId,uint256 price,string tokenUri)"),
      _tokenVoucher.collectionAddress,
      _tokenVoucher.tokenId,
      _tokenVoucher.price,
      keccak256(bytes(_tokenVoucher.tokenURI))
    )));
  }

   function redeem(address _redeemer, TokenVoucher memory _tokenVoucher, bytes memory _signature) external payable {
        address signer = _verify(_tokenVoucher, _signature);
        require(hasRole(MINTER_ROLE, signer), "Invalid signature or unauthorized");
        require(msg.value >= _tokenVoucher.price, "Have to send an amount equal to price");

        _safeMint(signer, _tokenVoucher.tokenId);
        _setTokenURI(_tokenVoucher.tokenId, _tokenVoucher.tokenURI);
        _transfer(signer, _redeemer, _tokenVoucher.tokenId);
        balance[signer] += msg.value;
        emit TokenMinted(_tokenVoucher.tokenId, _redeemer, _tokenVoucher.tokenURI);    
    }

    function _verify(TokenVoucher memory _tokenVoucher, bytes memory _signature) internal view returns (address) {
        bytes32 digest = _hash(_tokenVoucher);
        return digest.toEthSignedMessageHash().recover(_signature);
    }

    function withdraw() public {
        require(hasRole(MINTER_ROLE, msg.sender), "Only authorized minters can withdraw");

        address payable receiver = payable(msg.sender);

        uint amount = balance[receiver];
        // zero account before transfer to prevent re-entrancy attack
        balance[receiver] = 0;
        receiver.transfer(amount);
    }

  function getBalance() public view returns (uint256) {
        return balance[msg.sender];
    }

   function supportsInterface(bytes4 _interfaceId) public view virtual override (AccessControl, ERC721) returns (bool) {
        return ERC721.supportsInterface(_interfaceId) || AccessControl.supportsInterface(_interfaceId);
    }  

}