using System.Security.Claims;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Secwest.Benchmarks.AspnetAuthorization.Models;
using Secwest.Benchmarks.AspnetAuthorization.Repositories;

namespace Secwest.Benchmarks.AspnetAuthorization.Controllers;

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
        var customerClaim = User.FindFirstValue("customer_id");
        if (!int.TryParse(customerClaim, out var authenticatedCustomerId))
        {
            return Forbid();
        }

        var invoice = await _invoices.LoadInvoiceAsync(
            invoiceId,
            authenticatedCustomerId);
        return invoice is null ? NotFound() : Ok(invoice);
    }
}
