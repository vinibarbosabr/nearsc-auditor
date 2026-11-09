use rmcp::schemars;
use rmcp::{handler::server::wrapper::Parameters, tool, tool_router, transport::stdio, ServiceExt};
use serde::Deserialize;

#[derive(Debug, Deserialize, schemars::JsonSchema)]
struct EchoParams {
    /// Message to echo back
    message: String,
}

#[derive(Clone)]
struct NearscMcp;

#[tool_router(server_handler)]
impl NearscMcp {
    #[tool(description = "Echo a message back; hello-world tool for the nearsc MCP server")]
    fn echo(&self, Parameters(EchoParams { message }): Parameters<EchoParams>) -> String {
        format!("nearsc-mcp echo: {message}")
    }
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let service = NearscMcp.serve(stdio()).await?;
    service.waiting().await?;
    Ok(())
}
