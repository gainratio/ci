import {
  Directory,
  FoundationCheckEvidence,
  Secret,
  check,
  dag,
  func,
  object,
} from "@dagger.io/dagger"

const REPOSITORY = "hseshadr/ci"
const REPOSITORY_URL = "https://github.com/hseshadr/ci.git"
const COMMIT_SHA = "842187d3b9e549867375a37011cc75a520dc74a9"
const CONSUMER = `${REPOSITORY}@${COMMIT_SHA}`
const PRODUCER = `${"b".repeat(40)}:7`
const ALLOWED_ROOTS = ["dist"]
const FUNCTIONS_ROOTS = ["dist", "functions"]
const CACHE_NAMESPACE = "fixture-typescript-v1"
const SECRET_CANARY = ["typescript", "private", "canary"].join("-")
const ARTIFACT_NAME = "typescript-artifact.txt"
const TRANSPORT_MARKERS = ["api.cloudflare.com", "api.github.com", "wrangler"]
const PACKAGE_REPOSITORY = "hseshadr/edgeproc-core"
const PACKAGE_URL = "https://github.com/hseshadr/edgeproc-core.git"
const PACKAGE_SHA = "0bf2a8394b205f099b14b71303627ef871715622"
const PACKAGE_PROJECT = "edgeproc-core"
const PACKAGE_VERSION = "0.4.3"

@object()
export class TypescriptConsumer {
  @func()
  @check()
  async contract(): Promise<string> {
    await sourceGuard()
    const envelope = await verifiedEnvelope()
    const secret = dag.setSecret("typescript-fixture-secret", SECRET_CANARY)
    typedEvidence(secret)
    typedPagesEvidence(envelope, secret)
    await providerRejectsTamper(envelope, secret)
    await packageBuild()
    await dag.cacheVolume(CACHE_NAMESPACE).id()
    return "typescript fixture passed"
  }
}

async function sourceGuard(): Promise<void> {
  const history = dag.git(REPOSITORY_URL).commit(COMMIT_SHA).tree({ depth: 0, includeTags: true })
  const source = dag.foundation().source(history, REPOSITORY, COMMIT_SHA)
  await source.digest()
  await dag.foundation().guard(source, REPOSITORY, COMMIT_SHA).sync()
}

async function verifiedEnvelope(): Promise<Directory> {
  const artifact = dag.directory().withNewFile(`dist/${ARTIFACT_NAME}`, "typescript artifact")
  const envelope = dag.foundation().envelope(artifact, CONSUMER, PRODUCER, ALLOWED_ROOTS)
  const verified = dag.foundation().verifyEnvelope(envelope, CONSUMER, PRODUCER, ALLOWED_ROOTS)
  const entries = await verified.directory("dist").entries()
  if (entries.length !== 1 || entries[0] !== ARTIFACT_NAME) {
    throw new Error("verified TypeScript artifact boundary differs")
  }
  return envelope
}

function typedEvidence(secret: Secret): void {
  const evidence: FoundationCheckEvidence = dag.foundation().greenMain(secret, REPOSITORY)
  if (evidence === undefined) throw new Error("generated evidence type was unavailable")
}

function typedPagesEvidence(envelope: Directory, secret: Secret): void {
  void pagesEvidenceRoundTrip
  void envelope
  void secret
}

async function pagesEvidenceRoundTrip(envelope: Directory, secret: Secret): Promise<void> {
  const evidence = dag.cloudflarePages().deploy(
    envelope, secret, secret, secret, "7", 1, REPOSITORY, "ci", "main",
    "example.invalid", "dist", [], CONSUMER, PRODUCER, FUNCTIONS_ROOTS,
    { pagesFunctions: true },
  )
  const evidenceId = await evidence.id()
  const reloaded = dag.loadCloudflarePagesDeploymentEvidenceFromID(evidenceId)
  const [deploymentId, deploymentUrl] = await Promise.all([
    reloaded.deploymentId(),
    reloaded.deploymentUrl(),
  ])
  if (deploymentId.length === 0 || deploymentUrl.length === 0) {
    throw new Error("reloaded Pages evidence was incomplete")
  }
}

async function packageBuild(): Promise<void> {
  const history = dag.git(PACKAGE_URL).commit(PACKAGE_SHA).tree({ depth: 0, includeTags: true })
  const built = dag.pythonPackage().build(
    history, PACKAGE_REPOSITORY, PACKAGE_SHA, PACKAGE_PROJECT,
  )
  const version = await built.version()
  const entries = await built.directory().entries()
  if (version !== PACKAGE_VERSION || entries.length !== 2) {
    throw new Error("TypeScript package build evidence differs")
  }
}

async function providerRejectsTamper(envelope: Directory, secret: Secret): Promise<void> {
  const tampered = envelope.withNewFile(`artifact/dist/${ARTIFACT_NAME}`, "tampered")
  try {
    await preflight(tampered, secret)
  } catch (error: unknown) {
    requireSafeTamperError(error)
    return
  }
  throw new Error("provider accepted a tampered envelope")
}

async function preflight(envelope: Directory, secret: Secret): Promise<string> {
  return dag.cloudflarePages().preflight(
    envelope, secret, secret, secret, "7", 1, REPOSITORY, "ci", "main",
    "example.invalid", "dist", [], CONSUMER, PRODUCER, ALLOWED_ROOTS,
  )
}

function requireSafeTamperError(error: unknown): void {
  if (!(error instanceof Error)) throw error
  const message = String(error)
  if (!message.toLowerCase().includes("artifact bytes or modes differ from manifest")) {
    throw new Error("provider reached transport before envelope rejection")
  }
  if (TRANSPORT_MARKERS.some((marker) => message.includes(marker))) {
    throw new Error("provider emitted a transport marker for a rejected envelope")
  }
  if (message.includes(SECRET_CANARY)) throw new Error("provider error disclosed the typed secret")
}
