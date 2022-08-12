import {
  CONTRACTS,
  getIsTransferCompletedAlgorand,
  redeemOnAlgorand,
} from "@certusone/wormhole-sdk";
import { NETWORKS } from "./networks";
import { impossible, Payload } from "./vaa";
import {
  Account,
  Algodv2,
  assignGroupID,
  mnemonicToSecretKey,
  waitForConfirmation,
} from "algosdk";
import { TransactionSignerPair } from "@certusone/wormhole-sdk/lib/cjs/algorand";

async function signSendAndConfirmAlgorand(
  algodClient: Algodv2,
  txs: TransactionSignerPair[],
  wallet: Account
) {
  assignGroupID(txs.map((tx) => tx.tx));
  const signedTxns: Uint8Array[] = [];
  for (const tx of txs) {
    if (tx.signer) {
      signedTxns.push(await tx.signer.signTxn(tx.tx));
    } else {
      signedTxns.push(tx.tx.signTxn(wallet.sk));
    }
  }
  await algodClient.sendRawTransaction(signedTxns).do();
  const result = await waitForConfirmation(
    algodClient,
    txs[txs.length - 1].tx.txID(),
    1
  );
  return result;
}

export async function execute_algorand(
  payload: Payload,
  vaa: Uint8Array,
  environment: "MAINNET" | "TESTNET" | "DEVNET"
) {
  const chainName = "algorand";
  let n = NETWORKS[environment][chainName];
  if (!n.key) {
    throw Error(`No ${environment} key defined for Algorand`);
  }
  if (!n.rpc) {
    throw Error(`No ${environment} rpc defined for Algorand`);
  }
  let contracts = CONTRACTS[environment][chainName];
  console.log("contracts", contracts);
  const ALGORAND_HOST = {
    algodToken: "",
    algodServer: n.rpc,
    algodPort: "",
  };
  if (environment === "DEVNET") {
    ALGORAND_HOST.algodToken =
      "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    ALGORAND_HOST.algodPort = "4001";
  }

  let target_contract: string;

  switch (payload.module) {
    case "Core":
      target_contract = contracts.core;
      // sigh...
      switch (payload.type) {
        case "GuardianSetUpgrade":
          console.log("Submitting new guardian set");
          break;
        case "ContractUpgrade":
          console.log("Upgrading core contract");
          break;
        default:
          impossible(payload);
      }
      break;
    case "NFTBridge":
      if (contracts.nft_bridge === undefined) {
        // NOTE: this code can safely be removed once the terra NFT bridge is
        // released, but it's fine for it to stay, as the condition will just be
        // skipped once 'contracts.nft_bridge' is defined
        throw new Error("NFT bridge not supported yet for terra");
      }
      target_contract = contracts.nft_bridge;
      switch (payload.type) {
        case "ContractUpgrade":
          console.log("Upgrading contract");
          break;
        case "RegisterChain":
          console.log("Registering chain");
          break;
        case "Transfer":
          console.log("Completing transfer");
          break;
        default:
          impossible(payload);
      }
      break;
    case "TokenBridge":
      if (contracts.token_bridge === undefined) {
        throw new Error("contracts.token_bridge is undefined");
      }
      target_contract = contracts.token_bridge;
      switch (payload.type) {
        case "ContractUpgrade":
          console.log("Upgrading contract");
          break;
        case "RegisterChain":
          console.log("Registering chain");
          break;
        case "Transfer":
          console.log("Completing transfer");
          break;
        case "AttestMeta":
          console.log("Creating wrapped token");
          break;
        case "TransferWithPayload":
          throw Error("Can't complete payload 3 transfer from CLI");
        default:
          impossible(payload);
          break;
      }
      break;
    default:
      target_contract = impossible(payload);
  }
  const target = BigInt(parseInt(target_contract));

  const CORE_ID = BigInt(parseInt(contracts.core));

  const algodClient = new Algodv2(
    ALGORAND_HOST.algodToken,
    ALGORAND_HOST.algodServer,
    ALGORAND_HOST.algodPort
  );
  const algoWallet: Account = mnemonicToSecretKey(n.key);

  if (await getIsTransferCompletedAlgorand(algodClient, target, vaa)) {
    console.log("Vaa has already been redeemed.");
    return;
  }

  // Create transaction
  const txs = await redeemOnAlgorand(
    algodClient,
    target,
    CORE_ID,
    vaa,
    algoWallet.addr
  );
  // Sign and send transaction
  const result = await signSendAndConfirmAlgorand(algodClient, txs, algoWallet);
  console.log("Confirmed in round:", result["confirmed-round"]);
}
