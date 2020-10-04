use bitcoin::node::Node;

#[tokio::main]
async fn main() -> std::io::Result<()> {
    let node: Node = Node::new();

    node.start().await?;

    Ok(())
}
