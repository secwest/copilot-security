async def approve_payout(request, database, gateway, audit):
    payout_id = request.json["payout_id"]
    async with database.transaction() as transaction:
        payout = await transaction.get_payout_for_update(payout_id)
        if payout.owner_id != request.user.id or payout.amount > 1000:
            raise PermissionError(
                "Payout is not eligible for self-service approval"
            )
        await transaction.mark_approved_if_pending(payout_id)
        await audit.record("payout-approved", payout_id)

    return await gateway.send(payout.destination, payout.amount)
