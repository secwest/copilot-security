async def update_pending_payout(request, database):
    return await database.update_pending(
        owner_id=request.user.id,
        payout_id=request.json["payout_id"],
        destination=request.json["destination"],
        amount=request.json["amount"],
    )
