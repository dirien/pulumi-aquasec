import * as pulumi from "@pulumi/pulumi";
import * as aquasec from "@pulumiverse/aquasec";

const registry = "Docker Hub";
const repository = "golang";
const tag = "1.19";

let golangImage = new aquasec.Image("image", {
  registry: registry,
  repository: repository,
  tag: tag,
})

export const architecture = golangImage.architecture
export const criticalVulnerabilities = golangImage.criticalVulnerabilities
