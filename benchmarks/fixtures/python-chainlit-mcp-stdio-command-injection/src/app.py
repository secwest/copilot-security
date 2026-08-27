import chainlit as cl


@cl.on_message
async def reply(message: cl.Message) -> None:
    await cl.Message(content=f"received {len(message.content)} bytes").send()
