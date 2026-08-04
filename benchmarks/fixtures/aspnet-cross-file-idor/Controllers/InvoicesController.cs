using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Secwest.Benchmarks.AspnetIdor.Models;
using Secwest.Benchmarks.AspnetIdor.Repositories;

namespace Secwest.Benchmarks.AspnetIdor.Controllers;

[ApiController]
[Authorize]
[Route("api/invoices")]
public sealed class InvoicesController : ControllerBase
{
    private readonly InvoiceRepository _invoices;

    public InvoicesController(InvoiceRepository invoices)
    {
        _invoices = invoices;
    }

    [HttpGet("{invoiceId:int}")]
    public async Task<ActionResult<Invoice>> Get([FromRoute] int invoiceId)
    {
        var invoice = await _invoices.LoadInvoiceAsync(invoiceId);
        return invoice is null ? NotFound() : Ok(invoice);
    }
}
