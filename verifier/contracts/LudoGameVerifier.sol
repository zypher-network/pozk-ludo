// SPDX-License-Identifier: GPL-3.0-only
pragma solidity ^0.8.20;

import "@openzeppelin/contracts/utils/introspection/ERC165.sol";
import "@openzeppelin/contracts-upgradeable/access/OwnableUpgradeable.sol";
import "@openzeppelin/contracts-upgradeable/proxy/utils/Initializable.sol";

import "./IVerifier.sol";

contract LudoGameVerifier is Initializable, OwnableUpgradeable, ERC165, IVerifier {
    // Scalar field size
    uint256 constant r = 21888242871839275222246405745257275088548364400416034343698204186575808495617;
    // Base field size
    uint256 constant q = 21888242871839275222246405745257275088696311157297823662689037894645226208583;

    // Verification Key data
    uint256 constant alphax = 8438842903283024337627335834852503501471075569961518161756143697280213113698;
    uint256 constant alphay = 2009731345434485647917104503443973137823768190402103508953868744948717393439;
    uint256 constant betax2 = 17236452894184093764686210694294128601421621194697681936533927612163997217079;
    uint256 constant betax1 = 11869009388718916303890138000871882330574599799729768844080597833174338650728;
    uint256 constant betay2 = 19463154154753310876833595253958991276598347706379831433515712524849363747582;
    uint256 constant betay1 = 20872851163111742520307769544683621590125178968975698755510532428078554252858;
    uint256 constant gammax2 = 21338177806025808754785526505356689219309531930693932024286531971820431680849;
    uint256 constant gammax1 = 10741367160870361514301822365537658483740622893520569247132203655506327757880;
    uint256 constant gammay2 = 18701238526014603500896062884211667625331994937973907658840119782954472106006;
    uint256 constant gammay1 = 16636195481809840744992695583438272310463964062254910373265606642366104956198;
    uint256 constant deltax2 = 8839131188409602199110899030864698770683870813582615138005301874096962603458;
    uint256 constant deltax1 = 16300990676326031772492625939120112186202692210559030196008800077893640108297;
    uint256 constant deltay2 = 9292284001673715872276554295046715683165722474575737795386500266689341603805;
    uint256 constant deltay1 = 20642117766413707969366969882367011515087613157045057284168466831713692781040;

    uint256 constant IC0x = 1515691947786173572046155870038527259659037541365618233932778862804299994319;
    uint256 constant IC0y = 21049717168302976248817916780105605238823937976660721093473639552263368328090;

    uint256 constant IC1x = 14630052775128445628922931974704065290133575298337112620791550795273345296971;
    uint256 constant IC1y = 18111842430233042823457370737337702457005006018763242713811979357819874996740;

    uint256 constant IC2x = 12663963462392095204150772850983655974635981362133905573258247331985438071027;
    uint256 constant IC2y = 13967010698294143608412153928404158438749438538634676395864629485068609975812;

    // Memory data
    uint16 constant pVk = 0;
    uint16 constant pPairing = 128;
    uint16 constant pLastMem = 896;

    function supportsInterface(bytes4 interfaceId) public view virtual override(ERC165) returns (bool) {
        return interfaceId == type(IVerifier).interfaceId || super.supportsInterface(interfaceId);
    }

    function name() external pure returns (string memory) {
        return "ludo";
    }

    function permission(address _sender) external view returns (bool) {
        return true;
    }

    /// show how to serialize/deseriaze the inputs params
    /// e.g. "uint256,bytes32,string,bytes32[],address[],ipfs"
    function inputs() external pure returns (string memory) {
        return "uint256[][]";
    }

    /// show how to serialize/deserialize the publics params
    /// e.g. "uint256,bytes32,string,bytes32[],address[],ipfs"
    function publics() external pure returns (string memory) {
        return "uint256[2][]";
    }

    function types() external pure returns (string memory) {
        return "zk";
    }

    struct Proof {
        uint[2] _pA;
        uint[2][2] _pB;
        uint[2] _pC;
    }

    function verify(bytes calldata _publics, bytes calldata _proof) external view returns (bool) {
        uint[2][] memory mPublics = abi.decode(_publics, (uint[2][]));
        Proof[] memory mProofs = abi.decode(_proof, (Proof[]));
        for (uint i = 0; i < mPublics.length; i++) {
            bool res = this.verifyProof(mProofs[i]._pA, mProofs[i]._pB, mProofs[i]._pC, mPublics[i]);
            if (!res) {
                return false;
            }
        }
        return true;
    }

    // _proof = [A, B ,C]
    function verifyProof(
        uint[2] calldata _pA,
        uint[2][2] calldata _pB,
        uint[2] calldata _pC,
        uint256[2] calldata _pubSignals
    ) public view returns (bool) {
        assembly {
            function checkField(v) {
                if iszero(lt(v, q)) {
                    mstore(0, 0)
                    return(0, 0x20)
                }
            }

            // G1 function to multiply a G1 value(x,y) to value in an address
            function g1_mulAccC(pR, x, y, s) {
                let success
                let mIn := mload(0x40)
                mstore(mIn, x)
                mstore(add(mIn, 32), y)
                mstore(add(mIn, 64), s)

                success := staticcall(sub(gas(), 2000), 7, mIn, 96, mIn, 64)

                if iszero(success) {
                    mstore(0, 0)
                    return(0, 0x20)
                }

                mstore(add(mIn, 64), mload(pR))
                mstore(add(mIn, 96), mload(add(pR, 32)))

                success := staticcall(sub(gas(), 2000), 6, mIn, 128, pR, 64)

                if iszero(success) {
                    mstore(0, 0)
                    return(0, 0x20)
                }
            }

            function checkPairing(pA, pB, pC, pubSignals, pMem) -> isOk {
                let _pPairing := add(pMem, pPairing)
                let _pVk := add(pMem, pVk)

                mstore(_pVk, IC0x)
                mstore(add(_pVk, 32), IC0y)

                // Compute the linear combination vk_x

                g1_mulAccC(_pVk, IC1x, IC1y, calldataload(add(pubSignals, 0)))

                g1_mulAccC(_pVk, IC2x, IC2y, calldataload(add(pubSignals, 32)))

                // -A
                mstore(_pPairing, calldataload(pA))
                mstore(add(_pPairing, 32), mod(sub(q, calldataload(add(pA, 32))), q))

                // B
                mstore(add(_pPairing, 64), calldataload(pB))
                mstore(add(_pPairing, 96), calldataload(add(pB, 32)))
                mstore(add(_pPairing, 128), calldataload(add(pB, 64)))
                mstore(add(_pPairing, 160), calldataload(add(pB, 96)))

                // alpha1
                mstore(add(_pPairing, 192), alphax)
                mstore(add(_pPairing, 224), alphay)

                // beta2
                mstore(add(_pPairing, 256), betax1)
                mstore(add(_pPairing, 288), betax2)
                mstore(add(_pPairing, 320), betay1)
                mstore(add(_pPairing, 352), betay2)

                // vk_x
                mstore(add(_pPairing, 384), mload(add(pMem, pVk)))
                mstore(add(_pPairing, 416), mload(add(pMem, add(pVk, 32))))

                // gamma2
                mstore(add(_pPairing, 448), gammax1)
                mstore(add(_pPairing, 480), gammax2)
                mstore(add(_pPairing, 512), gammay1)
                mstore(add(_pPairing, 544), gammay2)

                // C
                mstore(add(_pPairing, 576), calldataload(pC))
                mstore(add(_pPairing, 608), calldataload(add(pC, 32)))

                // delta2
                mstore(add(_pPairing, 640), deltax1)
                mstore(add(_pPairing, 672), deltax2)
                mstore(add(_pPairing, 704), deltay1)
                mstore(add(_pPairing, 736), deltay2)

                let success := staticcall(sub(gas(), 2000), 8, _pPairing, 768, _pPairing, 0x20)

                isOk := and(success, mload(_pPairing))
            }

            let pMem := mload(0x40)
            mstore(0x40, add(pMem, pLastMem))

            // Validate that all evaluations ∈ F

            checkField(calldataload(add(_pubSignals, 0)))

            checkField(calldataload(add(_pubSignals, 32)))

            // Validate all evaluations
            let isValid := checkPairing(_pA, _pB, _pC, _pubSignals, pMem)

            mstore(0, isValid)
            return(0, 0x20)
        }
    }
}
