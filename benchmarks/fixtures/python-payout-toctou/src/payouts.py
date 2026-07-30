async def approve_payout(request, database, gateway, audit):
    payout_id = request.json["payout_id"]
    reviewed = await database.get_payout(payout_id)
    if reviewed.owner_id != request.user.id or reviewed.amount > 1000:
        raise PermissionError("Payout is not eligible for self-service approval")

    await audit.record("payout-approved", payout_id)
    await database.mark_approved(payout_id)
    current = await database.get_payout(payout_id)
    return await gateway.send(current.destination, current.amount)
