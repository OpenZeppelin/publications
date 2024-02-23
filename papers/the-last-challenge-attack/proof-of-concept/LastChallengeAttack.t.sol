pragma solidity ^0.8.19;

import {VulnerablePlonkVerifier} from "../../contracts/verifiers/VulnerablePlonkVerifier.sol";
import {console2} from "forge-std/console2.sol";
import "forge-std/Test.sol";

// `forge test --match-test test_VerifyValidProof -vvv`
// `forge test --match-test test_ForgeProof -vvv`

contract LastChallengeAttack is Test {
    uint256 private constant r_mod = 21888242871839275222246405745257275088548364400416034343698204186575808495617; // prime order of BN254
    uint256 private constant p_mod = 21888242871839275222246405745257275088696311157297823662689037894645226208583; // p for field elements in [| 0, p-1 |] of BN254 (also called ALT_BN_128)
    
    // Calldata offsets in the proof, taken from VulnerablePlonkVerifier
    uint256 private constant proof_batch_opening_at_zeta_x = 0x2c0; // [Wzeta]
    uint256 private constant proof_batch_opening_at_zeta_y = 0x2e0;

    //Bn254.G1Point opening_at_zeta_omega_proof;      // [Wzeta*omega]
    uint256 private constant proof_opening_at_zeta_omega_x = 0x300;
    uint256 private constant proof_opening_at_zeta_omega_y = 0x320;

    uint256 private constant proof_quotient_polynomial_at_zeta = 0x280; // t(zeta) 

    VulnerablePlonkVerifier plonkVerifier;
    bytes public proof;
    bytes public stateTransitionHash;

    function setUp() public {
        plonkVerifier = new VulnerablePlonkVerifier();
        
        // Valid proof from which some elements will be replaced
        proof = hex"23821aca8b8a72a2a672434960684640782865bde1d2a6e9f238a2b9cf4c16e203fd6a2b35336aaabc373367d14ec67e82460e9eb2008699f7e055f43b3718132179526db856e99b57ab0d38e1d69439e399ac5bbdf766c36c756575f8dc34c618f3606f7f79487c8bc55a1817eb4b04c679d241b9f98b86ab6364fe6d00318e08017a7a933de03ee950f3fbe5840004d2ce7f9c48d667ecebaad9cd4cc4f47f14924655d581db624b02f3fa1b2022c53c23dfff612eaa4458a38f23bb5a58da125dbaa7b4053189f3c800c28641288b0a7c75d04591c99a1b0666b27db7518d18ff1d42273551e0edc1d73369aa420e83ee905ba1446022c7a75b82973497222a111728c313484f6a2f726950af07850216a09b912c94085d2da660646c5f4908b8927c36ba13dc60ae28d071e9c604fadb66dbaf4979cc447e074c328f278e1cfc649e531783b23c2f469d1e90d58888fe9bb3b65b806f2632eb5aca2f43e716d734fdb03ba8867997c478c5cb72418643a1bb4eeae181c4692dc77b01882f007adb191885268d29282ba206121ba54ec5ff1281195b1aa3894e2bfa3ca084173105c58f474d672ad59b39e1e601e9651627a778417a6f1dcfe7c8342211f221361a8ed2f748f7788e749dfa67d7131af40f2d5fbb4a35c01067b59c82e0740bc73c321863e4cb34122de56506d1b90baa3227776b92f788edb61f0d828a2317db3fd6ad6a6bd30425a86c0c4f80b64b21fd695511bc612f8bdc479adfa92314f52136bde78a5adec621ad9b61ec7920e18de55d068989259fefa8d55dc97d1e37120849dbbc4440b81e335b897e977349cf0e055ce36495132be24bfe45da1db587822115120fc15572ce3e0723e1d90abc940a873bb83c4d64a481f331d8075f452867978605a93b282ad4e5a94b339e5203070d192ab7dac31312048cba13c44edfea3fc4ec9b958d855b6a3a494f1c5b1832678fce81856aed4265b27627c2d582bd3c8ce87212cefb03893db38388030fca44cdbb4d43c98c2d731633241ff322819cb59e9b36c09eeb9a8f043c76db4a7b924a288c137d6b8ce2a0592c69548a780e32eff92812c87b1ea92777050064fdd83ca7f832d61ccec422002567d8e41b950cd07c211ba711f1022a799f4277af8bb4ddff625d5cacc6c00210540550aa0aaf3a4bf4d27d528814d0673b6a9cf0614562a5cb020a2aeb8b281dcccfb2a3c8a85652cb4cd96db617c001edf3fde0b79489ac8712fbefa7c7f8214459c97cdddc6ef1ea85cb7bc587c309983fa4c7b8c5dc410ee3a27f1c4d6b";
        // Public input
        stateTransitionHash = hex"3041a1027bacc392df45fe2e0a35293974440621ecf1efca11e5359819869829";
    }

    function test_VerifyValidProof() external returns (bool) {
        // Verify that a valid proof passes.
        uint256[] memory public_inputs = new uint256[](1);
        public_inputs[0] = uint256(bytes32(stateTransitionHash));

        bool success = plonkVerifier.Verify(proof, public_inputs);
        assertTrue(success);
    }

     function test_ForgeProof() external returns (bool) {
        // We forge a proof for the following falsified input: 
        uint256 falsifiedInput = uint256(bytes32(keccak256(abi.encodePacked("RANDOM_INPUT_SELECTED_BY_THE_PROVER")))) % r_mod;
        
        console2.log("Changing the public input from %s to %s", uint256(bytes32(stateTransitionHash)), falsifiedInput);
        uint256[] memory public_inputs = new uint256[](1);
        public_inputs[0] = falsifiedInput; // Adding our falsified public input to the input array.

        // A and B were extracted from a valid proof and simply need to pass the pairing check. 
        // They are constant elliptic curve points respecting e(-A, [x]2) * e(B, [1]2) == 1.
        // They do not need to be changed. 
        uint256 A_x = uint256(bytes32(hex"2025b8d1546cb26b11c553e5de1c32b51157c50f0704b57d3b7ce9207c389000"));
        uint256 A_y = uint256(bytes32(hex"1ba9b9e7da413178cfe16b60ea0168ff19d49185139a1efc7259b5571d31725e"));
        uint256 B_x = uint256(bytes32(hex"25ea7385449dab9f1da965dccd945aca3d13457aa37a90ad7733b1e2c3e4447c"));
        uint256 B_y = uint256(bytes32(hex"0d3920133268ddc88f8b38444edee576a8b62650982675cb7529a105c9bfaa0e"));

        // If any proof element or public input is modified, C should be changed with the value obtained by 
        // uncommenting the associated custom error line 757 of `VulnerablePlonkVerifier.sol`.
        uint256 C_x = uint256(bytes32(hex"15d5de892c018dcbfca26818c5c168d3c31f4645092335423b8ea3d9d751f869"));
        uint256 C_y = uint256(bytes32(hex"0490339c44314a11f8bbfde19236ecd0c3045f6bd7545610718c6ae4c9d7ac73"));

        assembly{
            C_y := sub(p_mod, C_y) // C = - (F - E), reverse the sign of C
            A_y := sub(p_mod, A_y) // Reverse the sign of A
        }


        // `u` should be changed with the value obtained by uncommenting the associated custom error line 722 
        // of `VulnerablePlonkVerifier.sol`.
        uint256 u = uint256(bytes32(hex"2e0bc4e4d992d0d04a9ec0c03fa8698bac1682fab82541a1970a9b075b1de5bf"));
        
        // `z` and `w` should be changed with the value obtained by uncommenting the associated custom error line 775 
        // of `VulnerablePlonkVerifier.sol`.
        uint256 z = uint256(bytes32(hex"0d5baabd11563009b4e76732e77a22acd72b4d228f855a6d49cfc2e14a83110d"));
        uint256 w = uint256(bytes32(hex"2a734ebb326341efa19b0361d9130cd47b26b7488dc6d26eeccd4f3eb878331a"));

        // `X` and `Y` are elliptic curve points solving the system of equations
        // X + u*Y = A
        // z*X + z*ω*u*Y = C + B
        // They are thus the solution to find X = [Wz]1 and Y = [Wzω]1 passing step 12 of the PLONK verifier algorithm.
        // They are computed later as `X = [Wz]1 = (-u)*Y + A` and `Y = [Wzω]1 = 1/(zu(ω - 1)) * (C + B -zA)`.
        {
            console2.log("Solving the equations to find the batch openings [Wz]1 = X and [Wzw]1 = Y.");
            uint256 x_x; 
            uint256 x_y;
            uint256 y_x;
            uint256 y_y;

            assembly {
                function pow(x, e, mPtr) -> res { // Function returning x ** e % r for 32 bytes integer by calling `modexp` precompile
                    mstore(mPtr, 0x20) 
                    mstore(add(mPtr, 0x20), 0x20) 
                    mstore(add(mPtr, 0x40), 0x20)
                    mstore(add(mPtr, 0x60), x) 
                    mstore(add(mPtr, 0x80), e) 
                    mstore(add(mPtr, 0xa0), r_mod) 
                    let check_staticcall := staticcall(gas(), 0x05, mPtr, 0xc0, mPtr, 0x20) 
                    if eq(check_staticcall, 0) { 
                        revert(0,0)
                    }
                    res := mload(mPtr) 
                }

                let mPtr := mload(0x40) // Get free memory pointer
                
                let den := addmod(w, sub(r_mod, 1), r_mod) // den = w - 1 % r
                den := mulmod(den, u, r_mod) // den = u*(w-1) % r
                den := mulmod(den, z, r_mod) // den = z*u*(w-1) % r
                den := pow(den, sub(r_mod, 2), mPtr) // den = 1 / (z*u*(w-1)) % r

                mstore(mPtr, C_x) // Store args to compute C + B
                mstore(add(mPtr, 0x20), C_y) 
                mstore(add(mPtr, 0x40), B_x) 
                mstore(add(mPtr, 0x60), B_y)
                let l_success := staticcall(gas(), 6, mPtr, 0x80, mPtr, 0x40) // Stores C + B (x, y) to mPtr
                if iszero(l_success) {
                    revert(0,0)
                }

                mstore(add(mPtr, 0x40), A_x) // Store args to compute (-z) * A
                mstore(add(mPtr, 0x60), A_y)
                mstore(add(mPtr, 0x80), addmod(0, sub(r_mod, z), r_mod)) // -z
                l_success := staticcall(gas(), 7, add(mPtr, 0x40), 0x60, add(mPtr, 0x40), 0x40) // Computes (-z) * A, stores it to mPtr + 0x40
                if iszero(l_success) {
                    revert(0,0)
                }

                l_success := staticcall(gas(), 6, mPtr, 0x80, mPtr, 0x40) // Stores C + B - z * A (x, y) coordinates to mPtr
                if iszero(l_success) {
                    revert(0,0)
                }

                mstore(add(mPtr, 0x40), den) // 1 / (z*u*(w-1))
                l_success := staticcall(gas(), 7, mPtr, 0x60, mPtr, 0x40) // Computes y = 1 / (z*u*(w-1)) * (C + B -zA) and stores it to mPtr
                if iszero(l_success) {
                    revert(0,0)
                }

                y_x := mload(mPtr) // `Y = [Wzω]1 = 1/(zu(ω - 1)) * (C + B -zA)`
                y_y := mload(add(mPtr, 0x20))

                den := addmod(0, sub(r_mod, u), r_mod) // den = -u % r
                mstore(mPtr, y_x) // x coordinate of C
                mstore(add(mPtr, 0x20), y_y) // y coordinate of C
                mstore(add(mPtr, 0x40), den) // (-u)
                l_success := staticcall(gas(), 7, mPtr, 0x60, mPtr, 0x40) // Computes (-u) * y and stores it to mPtr
                if iszero(l_success) {
                    revert(0,0)
                }

                mstore(add(mPtr, 0x40), A_x) // Store A to be able to compute A - uy
                mstore(add(mPtr, 0x60), A_y)
                l_success := staticcall(gas(), 6, mPtr, 0x80, mPtr, 0x40) // Stores A - uy (x, y) coordinates to mPtr
                if iszero(l_success) {
                    revert(0,0)
                }

                x_x := mload(mPtr) // X = [Wz]1 = (-u)*Y + A
                x_y := mload(add(mPtr, 0x20))
            }

            {
                // Getting X and Y coordinates as bytes
                bytes memory bytes_x_x = abi.encodePacked(x_x); 
                bytes memory bytes_x_y = abi.encodePacked(x_y);
                bytes memory bytes_y_x = abi.encodePacked(y_x);
                bytes memory bytes_y_y = abi.encodePacked(y_y);

                console2.log("Falsifying the batch openings.");

                // Looping over all the bytes.
                // We forge the proof by setting `[Wz]1 = X` and `[Wzω]1 = Y`
                for (uint i = 0; i < 32; i++) {
                    proof[proof_batch_opening_at_zeta_x + i] = bytes1(bytes_x_x[i]); 
                    proof[proof_batch_opening_at_zeta_y + i] = bytes1(bytes_x_y[i]);
                    proof[proof_opening_at_zeta_omega_x + i] = bytes1(bytes_y_x[i]);
                    proof[proof_opening_at_zeta_omega_y + i] = bytes1(bytes_y_y[i]);
                }
            }
        }

        // We also need to cheat the check done with the quotient polynomial, as the code uses an older version of PLONK.
        // This check is done at the end of the `verify_quotient_poly_eval_at_zeta` function.
        // To do so we need to set `t(ζ)` as `computed_quotient / state_zeta_power_n_minus_one` in the proof.
        {
            // `computed_quotient` and `state_zeta_power_n_minus_one` should be changed with the values obtained by uncommenting
            // the associated custom error line 1143 of `VulnerablePlonkVerifier.sol`.
            uint256 computed_quotient = uint256(bytes32(hex"2b23c1646440297942ba0adfecef0f414aa875cee58be1ac3ecfed8ea2b231d0"));
            uint256 state_zeta_power_n_minus_one = uint256(bytes32(hex"01e32b35a8da834d895fd6a9ff64844e09a7a252f53cf42bf6cdd96717ecc75b"));
            uint256 falsified_t_zeta;

            assembly {
                function pow(x, e, mPtr) -> res { // Function returning x ** e % r for 32 bytes integer by calling `modexp` precompile
                    mstore(mPtr, 0x20)
                    mstore(add(mPtr, 0x20), 0x20) 
                    mstore(add(mPtr, 0x40), 0x20) 
                    mstore(add(mPtr, 0x60), x) 
                    mstore(add(mPtr, 0x80), e) 
                    mstore(add(mPtr, 0xa0), r_mod) 
                    let check_staticcall := staticcall(gas(), 0x05, mPtr, 0xc0, mPtr, 0x20) 
                    if eq(check_staticcall, 0) { 
                        revert(0,0)
                    }
                    res := mload(mPtr) 
                }

                let mPtr := mload(0x40) // Get free memory pointer
                falsified_t_zeta := pow(state_zeta_power_n_minus_one, sub(r_mod, 2), mPtr) // 1 / (state_zeta_power_n_minus_one) % r
                falsified_t_zeta := mulmod(falsified_t_zeta, computed_quotient, r_mod) // t(ζ) = computed_quotient / (state_zeta_power_n_minus_one) % r
            }

            bytes memory bytes_falsified_t_zeta = abi.encodePacked(falsified_t_zeta); // Get `falsified_t_zeta` as bytes

            console2.log("Falsifying t(zeta).");
            for (uint i = 0; i < 32; i++) {
                proof[proof_quotient_polynomial_at_zeta + i] = bytes1(bytes_falsified_t_zeta[i]); // Set our forged t(ζ) in the proof
            }
        }

        bool success = plonkVerifier.Verify(proof, public_inputs); // Call the PLONK verifier
        assertTrue(success);
        if (success) {
            console2.log("Forgery successful.");
        }
    }
}