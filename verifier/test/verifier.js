
const { expect } = require("chai");

describe("Verify Contract", function () {
  it("Verify must success", async function () {
    const [owner] = await ethers.getSigners();
    const verifier = await ethers.deployContract("LudoGameVerifier");

    const res1 = await verifier.verifyProof(
      [
        "4434693717020178427255957419250397895579640211732044349670535279391287430565",
        "17367294148038272425423142175171006989478181862202267205339498098381000574908",
      ],
      [
        [
          "11054736525324957594977647826467594729404205813380890179784992235605132144988",
          "538436714147899032658407818857246788229544321811333257202652346523701745148",
        ],
        [
          "13605296580418911774920013080557670882077728076716518686118710004060254784464",
          "14402946269949369938237258819596444221746184896920421457043788965906491319266",
        ]
      ],
      [
        "6017795707918819398715036679212258005554588276697475595980006375576208880982",
        "12629741207411105190567867700787860383480007394951908634408499086554454306017"
      ],
      [
        "1",
        "1092739377885103454644040430160177557655257088",
      ],
    );
    expect(res1).to.equal(true);
  });


  it("verify with multiproof", async function () {
    const [owner] = await ethers.getSigners();
    const verifier = await ethers.deployContract("LudoGameVerifier");

    const res1 = await verifier.verify(
      "0x000000000000000000000000000000000000000000000000000000000000002000000000000000000000000000000000000000000000000000000000000000020000000000000000000000000000000000000000000000000000000000000001000000000000000000000000003100086a0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000001000000000000000000000000003100086a000000000000000000000000000000",
      "0x0000000000000000000000000000000000000000000000000000000000000020000000000000000000000000000000000000000000000000000000000000000207f205e25b4c17bf742ffdc77ef67035d4d5c801022f651870a9467f6d0405cd1d98d9e0303ae34877c63e5b0b00194902deae1d37132f257bea0c50111d28ad0fd2c3b1746cdaf082c64449fed5eb6eb300d9af44ee832268eab938d89eba710c1a7a3aeb6ca89c29ad552aaae393ee7b0587d6e377d872b3adc8947cc7731122cc5b324c374d9ee7c9cc835b73c10636aeb209d11bb4ceb4496961c7e8a2821af3e123038d8cdaad0364e6b92d19fc2e98cf7e198682d07650eab5244a311807918c0ba8586b46c1554ac79cfc8a23987bca6be46b3f4ea7e49a41931d7ec62dd40cc68cc6a23d593594089406ad37e54b2b98c061a9749a7bd69ab0ee2b9230048c0392dd6008069b38bbac1e8ad12338a8191013e3d2f2f86649190902902378e30f43153751cffbd28acc6f406991f98936a71893f8a8d26f51f502588a24d5be32f0bb95761a1e0f7402fffac4eade7e5d87b765ba7a1d0c1494526cd0193fdc7740a81fe988398e6769609eaf5e62e9239df3804636b9141915a581002e3fdf5629406933ef792ade82538aabc78ff38095a433f687cc03f1e5a124f822cf83234216fda0275e2810cb5a682af00a3b33ee24e5a7be643bfa001994cf241362a768f456c754ba6c297596c8d0056992c3434eddf4150096c9b33e303406ee7771738138f72d3e6f3a4b4d53466bd2afe4e2049fcd8632f6484a5e694e"
     );

    expect(res1).to.equal(true);
  });
});
